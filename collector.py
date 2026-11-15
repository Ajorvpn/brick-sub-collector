#!/usr/bin/env python3
"""
BrickVPN Subscription Collector & Tester (Multi-Stage)
======================================================

Reads subscription URLs from ``sources.txt``, fetches them concurrently with
``asyncio`` + ``aiohttp``, extracts proxy share links, runs them through a
multi-stage strict health pipeline:

  1. Deep config parsing (VLESS / VMess / Trojan / SS)
  2. DNS resolution + per-(IP,Port) deduplication
  3. Offline MaxMind GeoIP pre-filter (10 allowed countries, ~0.05s per 6k IPs)
  4. Dual-probe stability: TLS/SNI handshake + active payload/TTFB download
  5. Jitter/latency quality scoring & ranking
  6. Clean node renaming & per-country quota enforcement

Outputs are written to ``output/``:

  output/servers.txt          Top 5 nodes per country (max 50), plain text.
  output/sub.txt              Base64 of servers.txt (standard subscription).
  output/countries/{CODE}.txt            Up to 20 best nodes per country.
  output/countries/{CODE}_base64.txt     Base64 of the country file.
  output/protocols/{proto}.txt           Grouped by protocol.
  output/protocols/{proto}_base64.txt    Base64 of the protocol file.
  output/status.json             Detailed JSON health report.

Usage
-----
    python collector.py
"""

from __future__ import annotations

import asyncio
import base64
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import parse_qs, quote, unquote

import aiohttp

try:  # optional dependency: only needed for enc:v1: subscription output
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - only when the package is missing
    AESGCM = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SOURCES_FILE = "sources.txt"
OUTPUT_DIR = "output"
COUNTRIES_DIR = os.path.join(OUTPUT_DIR, "countries")
PROTOCOLS_DIR = os.path.join(OUTPUT_DIR, "protocols")

SERVERS_FILE = os.path.join(OUTPUT_DIR, "servers.txt")
SUB_FILE = os.path.join(OUTPUT_DIR, "sub.txt")
STATUS_FILE = os.path.join(OUTPUT_DIR, "status.json")

FETCH_TIMEOUT = 15.0
DNS_TIMEOUT = 5.0
GEOIP_CHUNK = 100
GEOIP_BATCH_DELAY = 1.5
# Upper bound on IPs sent to ip-api.com when the offline .mmdb is usable
# (the free endpoint allows 15 req/min, i.e. 1,500 IPs per minute).
GEOIP_API_FALLBACK_LIMIT = 200
PROBE_TIMEOUT = 2.5
PROBE_GAP = 0.1
# Active payload read budget (was 2.5s: silent endpoints burned the whole wait).
PAYLOAD_READ_TIMEOUT = 0.8
SS_PROBE_READ_TIMEOUT = 0.4
MAX_LATENCY_MS = 650
NON_TLS_PENALTY_MS = 150.0
MAX_CONCURRENT_PROBES = 240
MAX_CONCURRENT_DNS = 200

# Offline MaxMind GeoLite2 Country database (free, cached locally).
CACHE_DIR = ".cache"
MMDB_CACHE_PATH = os.path.join(CACHE_DIR, "Country.mmdb")
MMDB_TMP_PATH = os.path.join("/tmp", "Country.mmdb")
MMDB_MIN_BYTES = 100_000
MMDB_CANDIDATE_URLS: List[str] = [
    "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-Country.mmdb",
    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
]

# Real end-to-end tunnel verification: only nodes whose proxy stream actually
# answers generate_204 through Xray may reach the published subscriptions.
MAX_XRAY_CANDIDATES_PER_COUNTRY = 30
XRAY_BATCH_SIZE = 40
XRAY_PORT_BASE = 21000
XRAY_TEST_URL = "http://cp.cloudflare.com/generate_204"
XRAY_TEST_TIMEOUT = 4.5
# Listener readiness: a crashed config exits in milliseconds, so poll instead of
# sleeping blindly (an unchecked crash looked like "0 live nodes").
XRAY_READY_TIMEOUT = 2.5
XRAY_READY_POLL_INTERVAL = 0.1
# Below this many tunnel-verified nodes we keep the socket-verified set, so a
# broken/blocked Xray run can never collapse the subscription to a node or two.
MIN_XRAY_VERIFIED_NODES = 5

# OpenRay publishes per-link streak telemetry next to its feeds.
OPENRAY_CHECK_COUNTS_URLS: Tuple[str, ...] = (
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/"
    "output/check_counts.json",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/"
    "output/.state/check_counts.json",
)
OPENRAY_TELEMETRY_TIMEOUT = 5.0

MAIN_QUOTA_PER_COUNTRY = 5
COUNTRY_FILE_QUOTA = 20
# Per-operator subscription size (output/operators/{op}.txt).
OPERATOR_QUOTA = 30
OPERATOR_TAGS: Tuple[str, ...] = ("mci", "irancell", "tci")

PROXY_SCHEMES = ("vless", "vmess", "trojan", "ss")

# Service/OS ports that must never be probed as proxy endpoints.
BLOCKED_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 445,
    1433, 3306, 3389, 5432, 6379, 27017,
}

# Encrypted-only policy: plaintext endpoints on these ports never reach the
# main subscription (80/8080/8008 are plain HTTP, the rest are abused proxies).
PLAINTEXT_AND_ABUSED_PORTS: Set[int] = {80, 8080, 8008, 8880, 8388, 19999}

# Transports sing-box cannot consume; a node using one is useless downstream.
UNSUPPORTED_TRANSPORTS: Set[str] = {"xhttp", "splithttp", "kcp", "mkcp", "quic"}

# Ports a TLS proxy endpoint is realistically served on (ranking preference).
PREFERRED_TLS_PORTS: Set[int] = {443, 8443, 2053, 2083, 2087, 2096}
IRAN_VERIFIED_BONUS_MS: float = -150.0
PREFERRED_PORT_BONUS_MS: float = -35.0

# uTLS fingerprints that send the post-quantum X25519MLKEM768 key share, which
# Xray 26.9.8+ demands before it will accept a REALITY ClientHello.
PQC_SAFE_FINGERPRINTS: Set[str] = {"chrome", "firefox", "safari"}
HEX_CHARS: Set[str] = set("0123456789abcdefABCDEF")

# VLESS is preferred; deprecated VMess ranks last on an equal score.
PROTOCOL_SORT_OFFSET: Dict[str, float] = {
    "vless": -25.0,
    "trojan": 0.0,
    "vmess": 20.0,
}

# Ranking bonuses. A node that survived a real generate_204 tunnel through
# Xray always outranks a socket-only node, while staying in the same pool so
# every country can still fill its five slots.
XRAY_VERIFIED_BONUS_MS: float = -300.0
# Live carrier testing (v2rayN / Xray 26.9.9): VLESS + REALITY passed ~90%,
# while Trojan + raw/tcp + tls failed ~95%. Rank accordingly.
REALITY_SORT_BONUS_MS: float = -180.0
TROJAN_RAW_TLS_PENALTY_MS: float = 150.0
STREAK_BONUS_PER_HIT_MS: float = -4.0
IRAN_STREAK_BONUS_PER_HIT_MS: float = -12.0
MAX_STREAK_BONUS_MS: float = -120.0

# Domains valid ONLY as SNI camouflage, NEVER as the proxy's connect host.
# ``cloudflare.com`` is intentionally absent: legitimate CF-fronted nodes use it.
DECOY_ONLY_HOSTS: Set[str] = {
    "chatgpt.com", "openai.com", "apple.com", "icloud.com", "microsoft.com",
    "live.com", "office.com", "bing.com", "google.com", "youtube.com",
    "gstatic.com", "googleapis.com", "yahoo.com", "speedtest.net",
    "fast.com", "netflix.com", "spotify.com", "discord.com", "github.com",
    "gitlab.com", "amazon.com", "aws.amazon.com", "samsung.com",
    "mozilla.org", "firefox.com", "wikipedia.org", "telegram.org",
    # Dead PaaS endpoints: herokuapp/seenode resolve to blocked AWS Global
    # Accelerator ranges and answer with an immediate TCP RST inside Iran.
    "herokuapp.com", "seenode.app", "run-on-seenode.com",
    # PaaS hosting domains seen in carrier logs as "malformed ECHConfigList".
    "render.com", "onrender.com", "bluehost.com",
}

# Non-TLS transports/protocols that must answer the HTTP payload probe.
HTTP_PROBE_NETWORKS = ("ws", "http", "h2")
HTTP_PROBE_PROTOCOLS = ("vless", "vmess", "trojan")

PROXY_LINK_RE = re.compile(
    r"(?i)\b(" + "|".join(PROXY_SCHEMES) + r")://[^\s\"'<>()[\]\{\}]+"
)

PURE_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")

ALLOWED_COUNTRIES: Dict[str, Tuple[str, str]] = {
    "DE": ("\U0001F1E9\U0001F1EA", "Germany"),
    "FI": ("\U0001F1EB\U0001F1EE", "Finland"),
    "NL": ("\U0001F1F3\U0001F1F1", "Netherlands"),
    "GB": ("\U0001F1EC\U0001F1E7", "United Kingdom"),
    "FR": ("\U0001F1EB\U0001F1F7", "France"),
    "US": ("\U0001F1FA\U0001F1F8", "United States"),
    "CH": ("\U0001F1E8\U0001F1ED", "Switzerland"),
    "SE": ("\U0001F1F8\U0001F1EA", "Sweden"),
    "AT": ("\U0001F1E6\U0001F1F9", "Austria"),
    "CA": ("\U0001F1E8\U0001F1E6", "Canada"),
}


@dataclass
class NodeInfo:
    """Parsed + tested representation of a single proxy node."""

    protocol: str = ""
    host: str = ""
    port: int = 0
    tls_enabled: bool = False
    sni: Optional[str] = None
    network: str = "tcp"
    original_link: str = ""
    raw_link: str = ""
    security: str = ""
    path: str = "/"
    iran_verified: bool = False
    operator_tags: Set[str] = field(default_factory=set)
    # Set only when the node answered generate_204 through a real Xray tunnel.
    xray_verified: bool = False
    global_streak: int = 0
    iran_streak: int = 0

    resolved_ip: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    latency_1: Optional[float] = None
    latency_2: Optional[float] = None
    avg_latency_ms: Optional[int] = None
    jitter_ms: Optional[int] = None
    ping_ms: Optional[float] = None
    quality_score: Optional[float] = None
    clean_name: Optional[str] = None
    renamed_link: Optional[str] = None
    error: Optional[str] = None

    @property
    def key(self) -> Tuple[str, int]:
        return (self.host.lower(), self.port)

    @property
    def pure_ip(self) -> str:
        """Raw IP (or hostname) without the port.

        GeoIP lookups MUST use this value: ``ip_key`` contains ``:port`` and
        therefore matches nothing in an IP-keyed database or batch API.
        """
        return self.resolved_ip or self.host

    @property
    def ip_key(self) -> str:
        """(IP, Port) identity, used ONLY for network-endpoint deduplication."""
        return f"{self.resolved_ip or self.host}:{self.port}"


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


async def fetch_url(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
        ) as resp:
            resp.raise_for_status()
            return await resp.text(errors="replace")
    except Exception as exc:
        print(f"[fetch] ERROR {url}: {exc}")
        return None


async def fetch_all(urls: List[str]) -> List[Optional[str]]:
    connector = aiohttp.TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        return await asyncio.gather(*(fetch_url(session, u) for u in urls))


def try_base64_decode(text: str) -> Optional[str]:
    stripped = text.strip()
    if not stripped:
        return None
    if not PURE_BASE64_RE.fullmatch(stripped):
        return None
    pad = len(stripped) % 4
    if pad:
        stripped += "=" * (4 - pad)
    try:
        raw = base64.b64decode(stripped, validate=True)
    except Exception:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


_TRAILING_ARTIFACT_CHARS = ".,;:)]}>'\"`"


def _clean_link(link: str) -> str:
    """Unescape HTML entities (``&amp;``) and strip markdown/HTML artifacts.

    Scraped feeds routinely escape ``&`` as ``&amp;``; without unescaping it,
    ``parse_qs`` yields keys like ``amp;security`` and nodes lose their TLS/SNI
    classification while emitting broken URIs into the subscription files.
    """
    cleaned = html.unescape(html.unescape(link.strip()))
    cleaned = cleaned.replace("&amp;", "&")
    return cleaned.rstrip(_TRAILING_ARTIFACT_CHARS)


def extract_links(text: str) -> List[str]:
    found: List[str] = []
    decoded = try_base64_decode(text)
    candidates = [decoded] if decoded is not None else []
    candidates.append(text)
    for candidate in candidates:
        unescaped = html.unescape(candidate)
        for m in PROXY_LINK_RE.finditer(unescaped):
            link = _clean_link(m.group(0))
            if link:
                found.append(link)
    return found



# ---------------------------------------------------------------------------
# Deep config parsing
# ---------------------------------------------------------------------------


def _port_allowed(port: int) -> bool:
    """Valid TCP port that is not a service/OS port we must never probe."""
    return 1 <= port <= 65535 and port not in BLOCKED_PORTS


def _extract_query_params(query: str) -> Dict[str, str]:
    if not query:
        return {}
    parsed = parse_qs(query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in parsed.items()}


def _is_decoy_connect_host(host: str) -> bool:
    """True when *host* is a camouflage domain that cannot be a proxy host."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return True
    for decoy in DECOY_ONLY_HOSTS:
        if h == decoy or h.endswith("." + decoy):
            return True
    return False


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def _resolve_sni(candidate: Optional[str], host: str) -> Optional[str]:
    """SNI: explicit value first, else the host when it is a real domain."""
    value = (candidate or "").strip()
    if value:
        return value
    host_value = (host or "").strip()
    if host_value and not _is_ip_literal(host_value):
        return host_value
    return None


def classify_source_url(url: str) -> Tuple[bool, Set[str]]:
    """Return ``(iran_verified, operator_tags)`` for a source URL."""
    u = (url or "").strip().lower()
    tags: Set[str] = set()
    # ``output/country/*.txt`` feeds are latency-ranked, NOT inside-Iran tested.
    country_feed = "output/country/" in u
    keys = (
        "output_iran/",
        "mahsanet/mahsafreeconfig",
        "aistudio_iran_verified",
        "all_valid_proxies_for_iran",
    )
    iran_ok = any(k in u for k in keys) or (
        "sakha1370/openray" in u and not country_feed
    )
    if "aistudio_iran_verified" in u or "iran_top100_checked" in u:
        # Inside-Iran verified feeds are tested on both MCI and Irancell.
        iran_ok = True
        tags.update(("mci", "irancell"))
    if "/mci" in u or "mci_top" in u:
        tags.add("mci")
    if "/irancell" in u or "irancell_top" in u or "/mtn" in u:
        tags.add("irancell")
    if "/tci" in u or "tci_top" in u:
        tags.add("tci")
    return iran_ok, tags


def _merge_provenance(target: NodeInfo, other: NodeInfo) -> None:
    """Merge source provenance from a duplicate endpoint into *target*."""
    target.iran_verified = target.iran_verified or other.iran_verified
    target.operator_tags.update(other.operator_tags)
    target.xray_verified = target.xray_verified or other.xray_verified
    target.global_streak = max(target.global_streak, other.global_streak)
    target.iran_streak = max(target.iran_streak, other.iran_streak)


def is_main_pool_eligible(node: NodeInfo) -> bool:
    """Encrypted-only, sing-box compatible nodes may enter the main pool.

    A TLS node that connects to a raw IP *and* carries no domain SNI can never
    verify a certificate in Xray (``x509: certificate signed by unknown
    authority``) and has no camouflage name, so it is excluded here wherever it
    came from.
    """
    sni = (node.sni or "").strip()
    return (
        node.tls_enabled
        and node.protocol in ("vless", "trojan", "vmess")
        and node.port not in PLAINTEXT_AND_ABUSED_PORTS
        and not _is_decoy_connect_host(node.host)
        and bool(sni)
        and not _is_ip_literal(sni)
    )


# ---------------------------------------------------------------------------
# Cloudflare CIDR validation & clean-IP pool
# ---------------------------------------------------------------------------

CLOUDFLARE_ALL_IPV4_NETS: Tuple[ipaddress.IPv4Network, ...] = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    )
)

# Edge range Iranian carriers (MCI / Irancell) block at the IP layer.
BLOCKED_CF_NET: ipaddress.IPv4Network = ipaddress.ip_network("188.114.96.0/20")

DEFAULT_CF_CLEAN_IPS: Tuple[str, ...] = (
    "104.18.2.161",
    "104.17.147.22",
    "172.66.44.108",
    "104.19.144.83",
    "104.18.32.47",
)


def is_cloudflare_ip(ip_str: str) -> bool:
    """True when *ip_str* is an IPv4 address inside an official CF range."""
    try:
        ip_obj = ipaddress.ip_address((ip_str or "").strip())
        if not isinstance(ip_obj, ipaddress.IPv4Address):
            return False
        return any(ip_obj in net for net in CLOUDFLARE_ALL_IPV4_NETS)
    except ValueError:
        return False


def is_blocked_cloudflare_ip(ip_str: str) -> bool:
    """True when *ip_str* is inside the carrier-blocked CF edge range."""
    try:
        ip_obj = ipaddress.ip_address((ip_str or "").strip())
        return isinstance(ip_obj, ipaddress.IPv4Address) and (
            ip_obj in BLOCKED_CF_NET
        )
    except ValueError:
        return False


def is_safe_cloudflare_clean_ip(ip_str: str) -> bool:
    """A clean IP must be Cloudflare-owned and outside the blocked range."""
    return is_cloudflare_ip(ip_str) and not is_blocked_cloudflare_ip(ip_str)


def is_valid_reality_pbk(pbk: str) -> bool:
    """REALITY ``pbk`` must decode to a 32-byte X25519 public key.

    Both standard base64 (``+``/``/``) and URL-safe base64 (``-``/``_``) are
    accepted, and percent-encoded values are unquoted first: aggregators export
    the same key in all of these spellings.
    """
    raw = unquote((pbk or "").strip()).replace(" ", "+")
    if not (42 <= len(raw) <= 46):
        return False
    padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
    try:
        normalized = padded.replace("+", "-").replace("/", "_")
        decoded = base64.urlsafe_b64decode(normalized.encode("ascii"))
        return len(decoded) == 32
    except Exception:
        return False


def normalize_reality_pbk(pbk: str) -> Optional[str]:
    """Canonical unpadded base64url form of a REALITY public key.

    Xray 26.9.9 decodes ``realitySettings.publicKey`` with strict unpadded
    URL-safe base64 (``RawURLEncoding``); a key exported with ``+``/``/`` or
    ``=`` padding aborts the whole process with exit code 23.
    """
    raw = unquote((pbk or "").strip()).replace(" ", "+")
    if not (42 <= len(raw) <= 46):
        return None
    padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
    try:
        normalized = padded.replace("+", "-").replace("/", "_")
        decoded = base64.urlsafe_b64decode(normalized.encode("ascii"))
    except Exception:
        return None
    if len(decoded) != 32:
        return None
    return base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")


def is_valid_reality_sid(sid: str) -> bool:
    """REALITY short id: 0-16 hex chars. Odd lengths are valid in Xray."""
    raw = (sid or "").strip()
    if len(raw) > 16:
        return False
    return all(c in HEX_CHARS for c in raw)


def parse_node_info(link: str) -> Optional[NodeInfo]:
    # B1: unescape HTML entities (``&amp;``) before any URI/query parsing.
    clean = _clean_link(link)
    try:
        scheme, rest = clean.split("://", 1)
    except ValueError:
        return None
    scheme = scheme.lower()
    if scheme not in PROXY_SCHEMES:
        return None

    node = NodeInfo(protocol=scheme, original_link=clean, raw_link=clean)

    if scheme == "vmess":
        b64 = rest.split("#", 1)[0]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        try:
            cfg = json.loads(
                base64.b64decode(b64).decode("utf-8", errors="replace")
            )
        except Exception:
            return None
        if not isinstance(cfg, dict):
            return None
        # allowInsecure / insecure / verify_cert are stripped at shaping time
        # instead of dropping the node: most aggregator feeds carry them.
        host = str(cfg.get("add", "")).strip()
        port_raw = cfg.get("port", 0)
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            return None
        if not host or not _port_allowed(port):
            return None
        if _is_decoy_connect_host(host):
            return None

        net = str(cfg.get("net", "") or "").lower()
        if net in ("", "raw"):
            net = "tcp"
        if net in UNSUPPORTED_TRANSPORTS:
            return None

        node.host = host
        node.port = port
        node.network = net
        node.tls_enabled = str(cfg.get("tls", "")).lower() == "tls"
        node.security = "tls" if node.tls_enabled else ""
        node.sni = _resolve_sni(cfg.get("sni") or cfg.get("host"), host)
        node.path = str(cfg.get("path", "") or "/")
        if not node.tls_enabled and node.port in PLAINTEXT_AND_ABUSED_PORTS:
            return None
        return node

    if "#" in rest:
        rest_no_frag, _ = rest.split("#", 1)
    else:
        rest_no_frag = rest

    if "?" in rest_no_frag:
        rest_no_query, query = rest_no_frag.split("?", 1)
        params = _extract_query_params(query)
    else:
        rest_no_query = rest_no_frag
        params = {}

    if "@" in rest_no_query:
        authority = rest_no_query.rsplit("@", 1)[1]
    else:
        authority = rest_no_query

    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None
        host = authority[1:end]
        rest_after = authority[end + 1:]
        if rest_after.startswith(":"):
            port_str = rest_after[1:]
        else:
            port_str = ""
    else:
        if ":" in authority:
            host, port_str = authority.rsplit(":", 1)
        else:
            host = authority
            port_str = ""

    host = host.strip()
    try:
        port = int(port_str)
    except (TypeError, ValueError):
        return None
    if not host or not _port_allowed(port):
        return None

    node.host = host
    node.port = port

    # Decoy domains answer ``GET /`` instantly but are not proxy endpoints.
    if _is_decoy_connect_host(host):
        return None

    security = params.get("security", "").lower()
    net = (params.get("type", "") or "").lower()
    if net in ("", "raw"):
        net = "tcp"
    if net in UNSUPPORTED_TRANSPORTS:
        return None

    if scheme == "trojan":
        node.tls_enabled = True
        node.network = net
        node.security = "tls"
        node.sni = _resolve_sni(params.get("sni") or params.get("host"), host)
    elif scheme == "vless":
        node.tls_enabled = security in ("tls", "reality")
        node.network = net
        node.security = security if security in ("tls", "reality") else ""
        node.sni = _resolve_sni(params.get("sni") or params.get("host"), host)
    else:
        node.tls_enabled = False
        node.network = "tcp"
        node.security = ""
        node.sni = None

    node.path = params.get("path") or "/"

    if node.security == "reality":
        # Reality needs a domain SNI, a 32-byte X25519 public key and an
        # even-length hex short id; anything else dies in Xray 26.9.9.
        pbk = (params.get("pbk") or "").strip()
        sid = (params.get("sid") or "").strip()
        if not node.sni or _is_ip_literal(node.sni):
            return None
        if not is_valid_reality_pbk(pbk) or not is_valid_reality_sid(sid):
            return None

    # Encrypted-only policy for the main pool. ``ss://`` is always plaintext
    # and is excluded by protocol instead, so its parser stays permissive.
    if (
        not node.tls_enabled
        and node.port in PLAINTEXT_AND_ABUSED_PORTS
        and node.protocol != "ss"
    ):
        return None

    return node




# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------


async def resolve_hostname(host: str) -> Optional[str]:
    try:
        infos = await asyncio.wait_for(
            asyncio.get_event_loop().getaddrinfo(
                host, 0, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
            ),
            timeout=DNS_TIMEOUT,
        )
    except Exception:
        return None
    for _family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip:
            return ip
    return None


# ---------------------------------------------------------------------------
# Offline MaxMind GeoIP (GeoLite2-Country .mmdb) with ip-api.com fallback
# ---------------------------------------------------------------------------

_mmdb_reader: Any = None
_mmdb_init_done = False


def _open_mmdb(path: str) -> Any:
    try:
        import maxminddb
    except Exception:
        return None
    try:
        return maxminddb.open_database(path)
    except Exception:
        return None


def mmdb_available() -> bool:
    return _mmdb_reader is not None


def reset_mmdb_state() -> None:
    """Reset the cached .mmdb reader (used by tests)."""
    global _mmdb_reader, _mmdb_init_done
    _mmdb_reader = None
    _mmdb_init_done = False


def mmdb_lookup(ip: str) -> Optional[str]:
    """Look up an ISO country code for *ip* locally (microseconds).

    *ip* must be a raw IP address — never an ``ip:port`` pair.
    """
    reader = _mmdb_reader
    if reader is None or not ip:
        return None
    try:
        record = reader.get(ip)
    except Exception:
        return None
    if not isinstance(record, dict):
        return None
    for section_name in ("country", "registered_country"):
        section = record.get(section_name)
        if isinstance(section, dict):
            cc = section.get("iso_code")
            if isinstance(cc, str) and cc:
                return cc.upper()
    return None


async def _download_file(
    session: aiohttp.ClientSession, url: str, target: str
) -> bool:
    tmp = target + ".part"
    try:
        directory = os.path.dirname(target)
        if directory:
            os.makedirs(directory, exist_ok=True)
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=60.0)
        ) as resp:
            if resp.status != 200:
                return False
            data = await resp.read()
        if not data or len(data) < MMDB_MIN_BYTES:
            return False
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, target)
        return True
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


async def ensure_mmdb_database(
    session: Optional[aiohttp.ClientSession] = None,
) -> bool:
    """Load (or download + cache) the offline GeoLite2 Country database.

    Tries ``.cache/Country.mmdb``, then ``/tmp/Country.mmdb``, and finally
    downloads from the candidate mirrors. Returns ``True`` when a usable
    reader is available.
    """
    global _mmdb_reader, _mmdb_init_done
    if _mmdb_init_done:
        return _mmdb_reader is not None
    _mmdb_init_done = True

    for path in (MMDB_CACHE_PATH, MMDB_TMP_PATH):
        if os.path.exists(path):
            reader = _open_mmdb(path)
            if reader is not None:
                _mmdb_reader = reader
                print(f"[info] GeoIP offline database loaded from {path}")
                return True

    try:
        import maxminddb  # noqa: F401
    except Exception:
        print("[warn] maxminddb not installed; GeoIP falls back to ip-api.com")
        return False

    own_session = session is None
    if session is None:
        session = aiohttp.ClientSession()
    try:
        for url in MMDB_CANDIDATE_URLS:
            for target in (MMDB_CACHE_PATH, MMDB_TMP_PATH):
                if not await _download_file(session, url, target):
                    continue
                reader = _open_mmdb(target)
                if reader is not None:
                    _mmdb_reader = reader
                    print(f"[info] GeoIP offline database downloaded from {url}")
                    return True
                print(f"[warn] Downloaded GeoIP database from {url} is unusable")
    finally:
        if own_session:
            await session.close()

    print("[warn] Could not obtain an offline GeoIP database")
    return False

async def filter_by_geoip(
    session: aiohttp.ClientSession,
    nodes: List[NodeInfo],
    api_fallback_limit: Optional[int] = None,
) -> List[NodeInfo]:
    """Filter nodes by GeoIP (country code).

    Nodes must already have ``resolved_ip`` set. ``ip_key`` (which contains
    ``:port``) is used ONLY to deduplicate network endpoints; every country
    lookup uses ``node.pure_ip`` (a raw IP, never ``ip:port``).

    Primary resolver: local offline ``Country.mmdb`` (microseconds per node).
    Fallback: ``http://ip-api.com/batch`` for IPs the database does not know.
    """
    # Deduplicate by (resolved_ip, port)
    seen_keys: Set[str] = set()
    unique: List[NodeInfo] = []
    for n in nodes:
        if not n.resolved_ip:
            continue
        k = n.ip_key
        if k in seen_keys:
            continue
        seen_keys.add(k)
        unique.append(n)

    ip_to_country: Dict[str, Optional[str]] = {}
    offline_hits = 0

    # --- Primary: offline .mmdb lookup on the raw IP ---------------------
    if mmdb_available():
        for n in unique:
            ip = n.pure_ip
            if not ip or ip in ip_to_country:
                continue
            cc = mmdb_lookup(ip)
            if cc:
                ip_to_country[ip] = cc
                offline_hits += 1

    # --- Fallback: ip-api.com/batch for IPs missing from the database -----
    missing_ips: List[str] = []
    seen_missing: Set[str] = set()
    for n in unique:
        ip = n.pure_ip
        if not ip or ip in ip_to_country or ip in seen_missing:
            continue
        seen_missing.add(ip)
        missing_ips.append(ip)

    if api_fallback_limit is not None and len(missing_ips) > api_fallback_limit:
        print(
            f"[info] GeoIP ip-api.com fallback capped at {api_fallback_limit} of "
            f"{len(missing_ips)} unknown IP(s) to respect the rate limit"
        )
        missing_ips = missing_ips[:api_fallback_limit]

    for i in range(0, len(missing_ips), GEOIP_CHUNK):
        chunk = missing_ips[i : i + GEOIP_CHUNK]
        part = await _batch_geoip_with_retry(session, chunk)
        ip_to_country.update(part)
        if i + GEOIP_CHUNK < len(missing_ips):
            await asyncio.sleep(GEOIP_BATCH_DELAY)

    if offline_hits:
        print(f"[info] GeoIP offline .mmdb resolved {offline_hits} IP(s)")
    if missing_ips:
        print(f"[info] GeoIP ip-api.com fallback queried {len(missing_ips)} IP(s)")

    allowed: List[NodeInfo] = []
    for n in unique:
        cc = ip_to_country.get(n.pure_ip)
        n.country_code = cc
        if cc in ALLOWED_COUNTRIES:
            n.country_name = ALLOWED_COUNTRIES[cc][1]
            allowed.append(n)
        else:
            n.error = f"blocked country {cc or 'unknown'}"
    return allowed


async def _batch_geoip_with_retry(
    session: aiohttp.ClientSession, ips: List[str], max_retries: int = 1
) -> Dict[str, Optional[str]]:
    """Query ip-api.com/batch with one retry on 429 or failure."""
    result: Dict[str, Optional[str]] = {ip: None for ip in ips}
    if not ips:
        return result

    payload = [{"query": ip, "fields": "status,countryCode,query"} for ip in ips]
    for attempt in range(max_retries + 1):
        try:
            async with session.post(
                "http://ip-api.com/batch",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=20.0),
            ) as resp:
                if resp.status == 429:
                    # Rate limited: wait and retry once
                    await asyncio.sleep(3.0)
                    continue
                if resp.status != 200:
                    return result
                data = await resp.json(content_type=None)
        except Exception:
            return result

        if isinstance(data, list):
            for entry in data:
                if isinstance(entry, dict):
                    q = entry.get("query")
                    status = entry.get("status")
                    cc = entry.get("countryCode")
                    if q and status == "success":
                        result[q] = cc
                    elif q:
                        result[q] = None
        for ip in ips:
            result.setdefault(ip, None)
        return result

    return result


async def resolve_and_dedup_nodes(nodes: List[NodeInfo]) -> List[NodeInfo]:
    """Resolve hostnames to IPs and deduplicate by (resolved_ip, port).

    Drops private/loopback/unresolvable hosts. Sets node.resolved_ip
    on each surviving node.
    """
    sem = asyncio.Semaphore(MAX_CONCURRENT_DNS)

    async def _resolve(node: NodeInfo) -> None:
        async with sem:
            ip = await resolve_hostname(node.host)
            node.resolved_ip = ip

    await asyncio.gather(*(_resolve(n) for n in nodes))

    # Drop nodes that failed to resolve
    resolved = [n for n in nodes if n.resolved_ip]

    # Drop private/loopback IPs
    public = []
    for n in resolved:
        ip = n.resolved_ip
        if ip and _is_public_ip(ip):
            public.append(n)

    # Deduplicate by (resolved_ip, port), merging source provenance
    seen_ips: Dict[str, NodeInfo] = {}
    unique: List[NodeInfo] = []
    for n in public:
        k = n.ip_key
        existing = seen_ips.get(k)
        if existing is not None:
            _merge_provenance(existing, n)
            continue
        seen_ips[k] = n
        unique.append(n)

    return unique


def _is_public_ip(ip: str) -> bool:
    """Return True if *ip* is a public IPv4/IPv6 address (not private/loopback)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Dual-probe stability: real handshake + active payload (TTFB) verification
# ---------------------------------------------------------------------------

def _create_probe_ssl_context() -> ssl.SSLContext:
    """No-verify TLS context for the reachability probe only."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# Built exactly once at import time. ``ssl.create_default_context()`` reloads
# /etc/ssl/certs/ca-certificates.crt from disk on every call; doing that ~6,000
# times on the event loop added +400ms per probe and dropped 96% of nodes for
# exceeding MAX_LATENCY_MS.
_PROBE_SSL_CTX: ssl.SSLContext = _create_probe_ssl_context()


def _build_tls_context(node: Optional[NodeInfo] = None) -> ssl.SSLContext:
    """O(1) TLS context shared by every probe connection.

    Proxy endpoints legitimately serve camouflage SNIs, Cloudflare edge IPs and
    REALITY ephemeral certificates, so CA/hostname verification in this probe
    drops working nodes (the Part 3 regression). Certificate validity belongs to
    the client (or to REALITY's ``pbk``), and TLS nodes with no domain SNI are
    excluded up front by :func:`is_main_pool_eligible`.
    """
    return _PROBE_SSL_CTX


def _enforce_min_tls_version(node: NodeInfo, ssl_object: Any) -> None:
    """Drop REALITY nodes that did not negotiate TLS 1.3."""
    if (getattr(node, "security", "") or "").lower() != "reality":
        return
    version = ssl_object.version() if hasattr(ssl_object, "version") else None
    if isinstance(version, str) and version != "TLSv1.3":
        raise ssl.SSLError(
            f"reality negotiated {version}; TLS 1.3 is required"
        )

PAYLOAD_READ_BYTES = 4096
PAYLOAD_REQUEST_TEMPLATE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "\r\n"
)


WS_UPGRADE_NETWORKS = ("ws", "http", "h2", "httpupgrade")

# HTTP statuses that prove the endpoint is not a usable proxy path
# (Cloudflare 52x, gateway errors, explicit rejections).
PROBE_REJECT_STATUS: Set[int] = {
    403, 500, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526, 530,
}

WS_UPGRADE_TEMPLATE = (
    "GET {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)


def _build_payload_request(node: NodeInfo) -> bytes:
    """Active HTTP/WebSocket upgrade request used by the payload probe."""
    return PAYLOAD_REQUEST_TEMPLATE.format(host=node.sni or node.host).encode()


def _build_ws_upgrade_request(node: NodeInfo) -> bytes:
    """WebSocket upgrade request targeting the node's own configured path."""
    raw_path = getattr(node, "path", "") or ""
    req_path = raw_path if raw_path.startswith("/") else "/"
    return WS_UPGRADE_TEMPLATE.format(
        path=req_path, host=node.sni or node.host
    ).encode()


def _http_status_code(payload: bytes) -> Optional[int]:
    """Parse the status code out of an HTTP response head."""
    if not payload:
        return None
    first_line = payload.split(b"\r\n", 1)[0]
    parts = first_line.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass
    try:
        await writer.wait_closed()
    except Exception:
        pass


async def _open_connection(
    node: NodeInfo, timeout: Optional[float] = None
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to the node, completing a full TLS handshake when required.

    Raises on refused/reset connections and TLS failures, and refuses to return
    a TLS transport that negotiated no usable cipher.
    """
    ip = node.resolved_ip
    if not ip:
        raise ConnectionError("node has no resolved IP")

    deadline = PROBE_TIMEOUT if timeout is None else timeout

    if not node.tls_enabled:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, node.port), timeout=deadline
        )

    sni = node.sni or node.host
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(
            ip, node.port, ssl=_build_tls_context(node), server_hostname=sni
        ),
        timeout=deadline,
    )
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None or ssl_object.cipher() is None:
        await _close_writer(writer)
        raise ssl.SSLError("TLS transport negotiated no valid cipher")
    try:
        _enforce_min_tls_version(node, ssl_object)
    except ssl.SSLError:
        await _close_writer(writer)
        raise
    return reader, writer


async def _handshake_probe(node: NodeInfo) -> bool:
    """Probe 1: TCP connect + full TLS handshake with SNI and cipher check."""
    try:
        _reader, writer = await _open_connection(node)
    except Exception:
        return False
    await _close_writer(writer)
    return True


def _requires_http_response(node: NodeInfo) -> bool:
    """Non-TLS proxy endpoints that must answer the HTTP probe with bytes."""
    return not node.tls_enabled and (
        node.network in HTTP_PROBE_NETWORKS
        or node.protocol in HTTP_PROBE_PROTOCOLS
    )


async def _payload_probe(
    node: NodeInfo, timeout: Optional[float] = None
) -> Tuple[bool, int, float]:
    """Probe 2: protocol-aware reachability / TTFB verification.

    Returns ``(ok, payload_bytes, latency)``. Latency is the independent second
    connection (and TLS handshake) establishment time, replaced by real TTFB
    when payload flows.

    Strictness:
      * TLS endpoints must complete an independent handshake with a valid
        cipher. ``ws``/``http``/``h2``/``httpupgrade`` endpoints are asked for a
        WebSocket upgrade and are rejected only on non-HTTP junk or a gateway
        error status; a read timeout or a clean close passes.
      * ``tcp``/``raw``/``grpc``/``reality`` TLS endpoints are never written to:
        they close the socket on unauthenticated HTTP text, so EOF after a
        valid cipher must not drop them.
      * Non-TLS vless/vmess/trojan (and ws/http/h2 transports) must answer the
        HTTP probe with payload starting ``HTTP/`` inside PAYLOAD_READ_TIMEOUT.
      * Non-TLS ``ss://`` endpoints receive 32 random bytes; only an immediate
        reset drops them.
    """
    started = time.monotonic()
    try:
        reader, writer = await _open_connection(node, timeout=timeout)
    except Exception:
        return False, 0, (time.monotonic() - started) * 1000.0

    established_ms = (time.monotonic() - started) * 1000.0

    if node.tls_enabled:
        # A valid cipher is the whole verdict for non-HTTP transports.
        # Note: For Reality/TCP/gRPC, this check proves TLS handshake
        # reachability only, not VLESS/Trojan proxy authentication.
        if (node.network or "").lower() in WS_UPGRADE_NETWORKS:
            request = _build_ws_upgrade_request(node)
            try:
                writer.write(request)
                await asyncio.wait_for(
                    writer.drain(), timeout=PAYLOAD_READ_TIMEOUT
                )
            except (ssl.SSLError, OSError, asyncio.TimeoutError):
                await _close_writer(writer)
                return False, 0, established_ms
            except Exception:
                await _close_writer(writer)
                return False, 0, established_ms

            try:
                chunk = await asyncio.wait_for(
                    reader.read(PAYLOAD_READ_BYTES),
                    timeout=PAYLOAD_READ_TIMEOUT,
                )
            except asyncio.TimeoutError:
                await _close_writer(writer)
                return True, 0, established_ms
            except (ssl.SSLError, OSError):
                # Reset after a valid handshake is normal for WS servers.
                await _close_writer(writer)
                return True, 0, established_ms

            await _close_writer(writer)
            payload = chunk or b""
            if not payload:
                # Clean EOF after a valid cipher is not a failure.
                return True, 0, established_ms
            if not payload.startswith(b"HTTP/"):
                return False, len(payload), established_ms
            status = _http_status_code(payload)
            if status in PROBE_REJECT_STATUS:
                return False, len(payload), established_ms
            return True, len(payload), established_ms

        await _close_writer(writer)
        return True, 0, established_ms

    if not node.tls_enabled and node.protocol == "ss":
        request = os.urandom(32)
        read_timeout = SS_PROBE_READ_TIMEOUT
    else:
        request = _build_payload_request(node)
        read_timeout = PAYLOAD_READ_TIMEOUT

    try:
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=read_timeout)
    except (ssl.SSLError, OSError, asyncio.TimeoutError):
        await _close_writer(writer)
        return False, 0, established_ms
    except Exception:
        await _close_writer(writer)
        return False, 0, established_ms

    try:
        chunk = await asyncio.wait_for(
            reader.read(PAYLOAD_READ_BYTES), timeout=read_timeout
        )
    except asyncio.TimeoutError:
        await _close_writer(writer)
        # Silent peer: acceptable only where HTTP is not expected.
        if _requires_http_response(node):
            return False, 0, established_ms
        return True, 0, established_ms
    except (ssl.SSLError, OSError):
        await _close_writer(writer)
        return False, 0, established_ms

    await _close_writer(writer)

    payload = chunk or b""
    ttfb_ms = (time.monotonic() - started) * 1000.0
    if not payload:
        # Clean EOF without a single payload byte.
        if node.tls_enabled or _requires_http_response(node):
            return False, 0, established_ms
        return True, 0, established_ms
    if _requires_http_response(node) and not payload.startswith(b"HTTP/"):
        return False, len(payload), ttfb_ms
    return True, len(payload), ttfb_ms


async def verify_node_stability(node: NodeInfo) -> Optional[Dict[str, Any]]:
    """Probe 1 (handshake latency) then probe 2 (payload/TTFB), 0.1s apart."""
    start = time.monotonic()
    handshake_ok = await _handshake_probe(node)
    latency_1 = (time.monotonic() - start) * 1000.0
    if not handshake_ok:
        node.error = "handshake probe failed"
        return None

    await asyncio.sleep(PROBE_GAP)

    payload_ok, payload_bytes, latency_2 = await _payload_probe(node)
    if not payload_ok:
        node.error = "payload probe failed"
        return None

    avg_ms = round((latency_1 + latency_2) / 2)
    if avg_ms > MAX_LATENCY_MS:
        node.error = f"latency {avg_ms}ms above {MAX_LATENCY_MS}ms cap"
        return None

    jitter_ms = round(abs(latency_1 - latency_2))
    penalty = 0.0 if node.tls_enabled else NON_TLS_PENALTY_MS
    quality = avg_ms + (jitter_ms * 1.5) + penalty
    # Iran-verified sources are prefered; so are realistic TLS ports.
    if node.iran_verified:
        quality += IRAN_VERIFIED_BONUS_MS
    if node.tls_enabled and node.port in PREFERRED_TLS_PORTS:
        quality += PREFERRED_PORT_BONUS_MS

    node.latency_1 = latency_1
    node.latency_2 = latency_2
    node.avg_latency_ms = avg_ms
    node.jitter_ms = jitter_ms
    node.quality_score = quality
    return {
        "latency_1": latency_1,
        "latency_2": latency_2,
        "avg_latency_ms": avg_ms,
        "jitter_ms": jitter_ms,
        "quality_score": quality,
        "payload_bytes": payload_bytes,
    }


def subnet24_key(ip: str) -> str:
    """``/24`` bucket of an IPv4 address (hostnames are their own bucket)."""
    raw = (ip or "").strip()
    parts = raw.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return raw


def dedupe_by_pure_ip(nodes: List[NodeInfo]) -> List[NodeInfo]:
    """Keep the best node per IP, then put one node per ``/24`` subnet first.

    Overflow nodes (same subnet, different IP) are still returned so a country
    with a thin IP pool can fill its quota, but only after every distinct
    subnet has had a chance to contribute.
    """
    seen: Set[str] = set()
    by_ip: Dict[str, NodeInfo] = {}
    unique: List[NodeInfo] = []
    for n in nodes:
        ip = n.pure_ip
        if not ip:
            continue
        existing = by_ip.get(ip)
        if existing is not None:
            _merge_provenance(existing, n)
            continue
        seen.add(ip)
        by_ip[ip] = n
        unique.append(n)

    primary: List[NodeInfo] = []
    overflow: List[NodeInfo] = []
    seen_subnets: Set[str] = set()
    for n in unique:
        s24 = subnet24_key(n.pure_ip)
        if s24 in seen_subnets:
            overflow.append(n)
        else:
            seen_subnets.add(s24)
            primary.append(n)
    return primary + overflow


def compute_streak_bonus_ms(node: NodeInfo) -> float:
    """Ranking bonus from OpenRay's consecutive-check streak telemetry."""
    global_streak = max(int(getattr(node, "global_streak", 0) or 0), 0)
    iran_streak = max(int(getattr(node, "iran_streak", 0) or 0), 0)
    if global_streak <= 0 and iran_streak <= 0:
        return 0.0
    raw_bonus = (global_streak * STREAK_BONUS_PER_HIT_MS) + (
        iran_streak * IRAN_STREAK_BONUS_PER_HIT_MS
    )
    return max(MAX_STREAK_BONUS_MS, raw_bonus)


def _effective_sort_key(node: NodeInfo) -> Tuple[float, float]:
    """Ranking key: Xray-verified, REALITY, VLESS first; raw TCP Trojan last."""
    quality = (
        node.quality_score if node.quality_score is not None else float("inf")
    )
    xray_bonus = (
        XRAY_VERIFIED_BONUS_MS if getattr(node, "xray_verified", False) else 0.0
    )
    proto_offset = PROTOCOL_SORT_OFFSET.get(node.protocol, 0.0)
    sec = (getattr(node, "security", "") or "").lower()
    net = (node.network or "tcp").lower()
    is_reality = sec == "reality" or "security=reality" in (
        node.raw_link or ""
    ).lower()
    reality_bonus = REALITY_SORT_BONUS_MS if is_reality else 0.0
    # Carrier testing: Trojan + raw/tcp + tls failed ~95% of the time in Iran.
    trojan_raw_penalty = (
        TROJAN_RAW_TLS_PENALTY_MS
        if (node.protocol == "trojan" and not is_reality and net in ("tcp", "raw"))
        else 0.0
    )
    streak_bonus = compute_streak_bonus_ms(node)
    return (
        round(
            quality
            + xray_bonus
            + proto_offset
            + reality_bonus
            + trojan_raw_penalty
            + streak_bonus,
            2,
        ),
        quality,
    )


def _transport_bucket(node: NodeInfo) -> str:
    sec = (getattr(node, "security", "") or "").lower()
    net = (node.network or "tcp").lower()
    if sec == "reality" or "security=reality" in (node.raw_link or "").lower():
        return "reality"
    if net in ("ws", "httpupgrade"):
        return "ws-tls"
    if net == "grpc":
        return "grpc-tls"
    if net in ("http", "h2"):
        return "h2-tls"
    return "tcp-tls"


def select_diverse_top_nodes(nodes: List[NodeInfo], quota: int) -> List[NodeInfo]:
    """Pick up to *quota* nodes: distinct ``/24`` subnets first, round-robin
    across transport buckets so one transport never owns every slot.

    Nodes are ranked before deduplication, so when one IP carries several
    transports the best-ranked one is the one that survives.
    """
    if quota <= 0:
        return []
    ordered = dedupe_by_pure_ip(sorted(nodes, key=_effective_sort_key))
    if len(ordered) <= quota:
        return ordered

    buckets: Dict[str, List[NodeInfo]] = {}
    for n in ordered:
        buckets.setdefault(_transport_bucket(n), []).append(n)
    for pool in buckets.values():
        pool.sort(key=_effective_sort_key)

    # REALITY is the transport that actually works inside Iran (15 of 18 live
    # nodes in the carrier test), so it gets up to three of the five slots
    # before a dead ``tcp-tls`` Trojan is allowed in at all.
    bucket_order = [
        "reality", "ws-tls", "reality", "grpc-tls", "reality", "h2-tls",
        "tcp-tls",
    ]
    selected: List[NodeInfo] = []
    seen_subnets: Set[str] = set()
    made_progress = True
    while len(selected) < quota and made_progress:
        made_progress = False
        for b in bucket_order:
            pool = buckets.get(b, [])
            for idx, cand in enumerate(pool):
                s24 = subnet24_key(cand.pure_ip)
                if s24 not in seen_subnets:
                    selected.append(pool.pop(idx))
                    seen_subnets.add(s24)
                    made_progress = True
                    break
            if len(selected) >= quota:
                break

    if len(selected) < quota:
        selected_ids = {id(n) for n in selected}
        for n in ordered:
            if id(n) not in selected_ids:
                selected.append(n)
                if len(selected) >= quota:
                    break
    return selected



# ---------------------------------------------------------------------------
# Xray-core end-to-end tunnel verification (generate_204)
# ---------------------------------------------------------------------------


def _xray_network(value: str) -> str:
    """Map a share-link transport name onto an Xray stream network name."""
    net = (value or "").lower()
    if net in ("", "raw", "tcp"):
        return "tcp"
    if net == "http":
        return "h2"
    if net in ("ws", "httpupgrade", "grpc", "h2"):
        return net
    return "tcp"


def _split_uri_parts(
    link: str,
) -> Optional[Tuple[str, str, str, int, Dict[str, str]]]:
    """Split ``scheme://userinfo@host:port?query#fragment`` into its parts."""
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return None
    scheme = scheme.lower()
    if "#" in rest:
        rest = rest.split("#", 1)[0]
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)

    userinfo, _sep, authority = rest.rpartition("@")
    if authority.startswith("["):
        end = authority.find("]")
        if end == -1:
            return None
        host = authority[1:end]
        port_str = authority[end + 1:].lstrip(":")
    elif ":" in authority:
        host, port_str = authority.rsplit(":", 1)
    else:
        host, port_str = authority, ""
    try:
        port = int(port_str)
    except (TypeError, ValueError):
        return None
    return scheme, userinfo, host.strip(), port, _extract_query_params(query)


def _xray_reality_short_id(sid: str) -> str:
    """Xray hex-decodes ``shortId``; odd-length ids must be padded.

    ``infra/conf/reality.go`` right-pads (``sid + "0"``) before decoding, so
    mirroring that here keeps the intended bytes while remaining valid hex.
    """
    raw = (sid or "").strip().lower()
    if not raw:
        return ""
    if len(raw) % 2:
        return raw + "0"
    return raw


def _xray_reality_spider_x(spx: str) -> str:
    raw = (spx or "").strip()
    if not raw:
        return "/"
    return raw if raw.startswith("/") else "/" + raw


def _xray_stream_network_settings(
    network: str,
    path: str,
    host_header: str,
    service_name: str = "",
    multi_mode: bool = False,
) -> Dict[str, Any]:
    """Transport specific ``streamSettings`` block for an Xray outbound."""
    if network == "ws":
        headers: Dict[str, str] = {}
        if host_header:
            headers["Host"] = host_header
        return {"wsSettings": {"path": path or "/", "headers": headers}}
    if network == "grpc":
        return {
            "grpcSettings": {
                "serviceName": service_name,
                "multiMode": multi_mode,
            }
        }
    if network == "httpupgrade":
        return {"httpupgradeSettings": {"path": path or "/", "host": host_header}}
    if network == "h2":
        return {
            "httpSettings": {
                "path": path or "/",
                "host": [host_header] if host_header else [],
            }
        }
    return {}


def _build_xray_vmess_outbound(link: str, tag: str) -> Optional[Dict[str, Any]]:
    b64 = link[len("vmess://"):].split("#", 1)[0]
    pad = len(b64) % 4
    if pad:
        b64 += "=" * (4 - pad)
    try:
        cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(cfg, dict):
        return None

    address = str(cfg.get("add", "")).strip()
    try:
        port = int(cfg.get("port", 0))
    except (TypeError, ValueError):
        return None
    if not address or not (1 <= port <= 65535):
        return None

    network = _xray_network(str(cfg.get("net", "")))
    security = "tls" if str(cfg.get("tls", "")).lower() == "tls" else "none"
    stream: Dict[str, Any] = {"network": network, "security": security}
    sni = str(cfg.get("sni") or cfg.get("host") or "").strip()
    host_header = str(cfg.get("host") or "").strip()
    if security == "tls":
        # Xray 26.2.6+ removed "allowInsecure" entirely; emitting it aborts the
        # whole process at startup (migrated to "pinnedPeerCertSha256").
        stream["tlsSettings"] = {
            "serverName": sni or address,
            "fingerprint": str(cfg.get("fp") or "chrome"),
        }
    stream.update(
        _xray_stream_network_settings(
            network,
            str(cfg.get("path", "") or "/"),
            host_header,
            str(cfg.get("serviceName", "") or ""),
            str(cfg.get("mode", "")) == "multi",
        )
    )

    try:
        alter_id = int(cfg.get("aid", 0) or 0)
    except (TypeError, ValueError):
        alter_id = 0
    return {
        "tag": tag,
        "protocol": "vmess",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": port,
                    "users": [
                        {
                            "id": str(cfg.get("id", "")),
                            "alterId": alter_id,
                            "security": str(cfg.get("scy") or "auto"),
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }


def build_xray_outbound_for_node(
    node: NodeInfo, tag: str
) -> Optional[Dict[str, Any]]:
    """Build a complete Xray outbound JSON for *node*.

    The link is shaped first (clean IP, ``fp=chrome``, ``ech``/``allowInsecure``
    stripped), so the tunnel test exercises exactly what the client receives.
    """
    shaped = shape_node_for_iran(node, index=1)
    if not shaped:
        return None
    if shaped.lower().startswith("vmess://"):
        return _build_xray_vmess_outbound(shaped, tag)

    parts = _split_uri_parts(shaped)
    if parts is None:
        return None
    scheme, userinfo, host, port, params = parts
    if scheme not in ("vless", "trojan") or not host or not userinfo:
        return None

    security = (params.get("security") or "").lower()
    if security not in ("tls", "reality"):
        if (node.security or "").lower() == "reality":
            security = "reality"
        elif node.tls_enabled:
            security = "tls"
        else:
            security = "none"

    raw_type = (params.get("type") or node.network or "tcp").strip().lower()
    if raw_type in ("", "raw"):
        raw_type = "tcp"
    if raw_type in ("h2", "http"):
        # Xray 26.x dropped the legacy HTTP/2 tunnel (httpSettings); a config
        # that mentions it aborts the whole batch with exit code 23.
        return None
    network = _xray_network(raw_type)
    # A bogus headerType (aes-128-gcm, srtp, ...) never becomes tcpSettings:
    # plain TCP is the only shape Xray accepts for headerless transports.
    stream: Dict[str, Any] = {"network": network, "security": security}
    sni = (params.get("sni") or params.get("host") or node.sni or host).strip()
    host_header = (params.get("host") or "").strip()

    if security == "tls":
        # Xray 26.2.6+ removed "allowInsecure"; including it aborts startup.
        tls_settings: Dict[str, Any] = {
            "serverName": sni,
            "fingerprint": params.get("fp") or "chrome",
        }
        alpn_values = [
            a.strip() for a in (params.get("alpn") or "").split(",") if a.strip()
        ]
        valid_alpn = [a for a in alpn_values if a in ("h3", "h2", "http/1.1")]
        if valid_alpn:
            tls_settings["alpn"] = valid_alpn
        stream["tlsSettings"] = tls_settings
    elif security == "reality":
        clean_pbk = normalize_reality_pbk(params.get("pbk") or "")
        if not clean_pbk:
            # Xray rejects a non-canonical key and kills the whole batch.
            return None
        raw_sid = (params.get("sid") or "").strip().lower()
        if not is_valid_reality_sid(raw_sid):
            return None
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": params.get("fp") or "chrome",
            "publicKey": clean_pbk,
            "shortId": _xray_reality_short_id(raw_sid),
            "spiderX": _xray_reality_spider_x(unquote(params.get("spx") or "")),
        }

    stream.update(
        _xray_stream_network_settings(
            network,
            params.get("path") or node.path or "/",
            host_header,
            params.get("serviceName", ""),
            params.get("mode", "") == "multi",
        )
    )

    raw_flow = (params.get("flow") or "").strip()
    if scheme == "vless" and raw_flow not in (
        "",
        "xtls-rprx-vision",
        "xtls-rprx-vision-udp443",
    ):
        # Unknown flow values fail Xray's config validation.
        return None
    # XTLS Vision only exists on TCP; on ws/grpc/h2/httpupgrade Xray aborts with
    # "XTLS only supports TCP", so the flow is stripped there.
    safe_flow = (
        raw_flow if (network == "tcp" and security in ("tls", "reality")) else ""
    )

    if scheme == "vless":
        settings: Dict[str, Any] = {
            "vnext": [
                {
                    "address": host,
                    "port": port,
                    "users": [
                        {
                            "id": unquote(userinfo),
                            # Xray only accepts "none"; "auto"/"zero" crash.
                            "encryption": "none",
                            "flow": safe_flow,
                        }
                    ],
                }
            ]
        }
    else:
        settings = {
            "servers": [
                {
                    "address": host,
                    "port": port,
                    "password": unquote(userinfo),
                }
            ]
        }

    return {
        "tag": tag,
        "protocol": scheme,
        "settings": settings,
        "streamSettings": stream,
    }


def _xray_candidates(
    nodes: List[NodeInfo],
) -> Tuple[List[NodeInfo], List[NodeInfo]]:
    """Per-country capped candidates plus nodes that cannot be tunnelled."""
    eligible = [n for n in nodes if is_main_pool_eligible(n)]
    passthrough = [n for n in nodes if not is_main_pool_eligible(n)]

    by_country: Dict[str, List[NodeInfo]] = {}
    for n in sorted(eligible, key=_effective_sort_key):
        by_country.setdefault(n.country_code or "", []).append(n)

    selected: List[NodeInfo] = []
    for code in sorted(by_country):
        unique = dedupe_by_pure_ip(by_country[code])
        selected.extend(unique[:MAX_XRAY_CANDIDATES_PER_COUNTRY])
    return selected, passthrough


async def _xray_http_status(
    proxy: str, url: str, timeout: float
) -> Optional[int]:
    """Fetch *url* through the local Xray HTTP inbound at *proxy*."""
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as session:
            async with session.get(
                url, proxy=proxy, allow_redirects=False
            ) as resp:
                return resp.status
    except Exception:
        return None


def _tunnel_quality_score(node: NodeInfo, rtt_ms: float) -> float:
    """Re-rank a verified node on its real tunnel RTT."""
    quality = rtt_ms
    if node.iran_verified:
        quality += IRAN_VERIFIED_BONUS_MS
    if node.tls_enabled and node.port in PREFERRED_TLS_PORTS:
        quality += PREFERRED_PORT_BONUS_MS
    return quality


async def _probe_xray_port(index: int, node: NodeInfo) -> Optional[NodeInfo]:
    proxy = f"http://127.0.0.1:{XRAY_PORT_BASE + index}"
    started = time.monotonic()
    status = await _xray_http_status(proxy, XRAY_TEST_URL, XRAY_TEST_TIMEOUT)
    if status not in (200, 204):
        return None
    rtt_ms = (time.monotonic() - started) * 1000.0
    node.xray_verified = True
    node.ping_ms = round(rtt_ms, 1)
    node.avg_latency_ms = int(round(rtt_ms))
    node.quality_score = _tunnel_quality_score(node, rtt_ms)
    return node


async def _xray_listener_up(port: int, timeout: float = 0.15) -> bool:
    """True when something accepts a TCP connection on 127.0.0.1:*port*."""
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port), timeout=timeout
        )
    except Exception:
        return False
    try:
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
    return True


async def _wait_for_xray_ready(
    proc: Any, first_port: int, timeout: Optional[float] = None
) -> bool:
    """Wait for Xray listeners, bailing out the moment the process dies."""
    deadline = time.monotonic() + (
        XRAY_READY_TIMEOUT if timeout is None else timeout
    )
    while time.monotonic() < deadline:
        if getattr(proc, "returncode", None) is not None:
            return False
        if await _xray_listener_up(first_port):
            return True
        await asyncio.sleep(XRAY_READY_POLL_INTERVAL)
    return getattr(proc, "returncode", None) is None


async def _read_xray_error(proc: Any) -> str:
    """First stderr line of a crashed Xray process (never raises)."""
    stderr = getattr(proc, "stderr", None)
    if stderr is None:
        return ""
    try:
        data = await asyncio.wait_for(stderr.read(), timeout=0.5)
    except Exception:
        return ""
    if not data or not isinstance(data, (bytes, bytearray)):
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    return text.splitlines()[0][:200] if text else ""


async def _run_xray_batch(
    binary: str, batch: List[NodeInfo], _depth: int = 0
) -> List[NodeInfo]:
    """Run one xray instance for *batch* and return the nodes that answer 204.

    A batch whose process dies (bad config / removed option) is split in half
    and retried once; if the retry also crashes the nodes are kept, because a
    Xray quirk must never wipe out the subscription.
    """
    inbounds: List[Dict[str, Any]] = []
    outbounds: List[Dict[str, Any]] = []
    rules: List[Dict[str, Any]] = []
    valid: List[Tuple[int, NodeInfo]] = []

    for idx, node in enumerate(batch):
        outbound = build_xray_outbound_for_node(node, f"out_{idx}")
        if outbound is None:
            continue
        inbounds.append(
            {
                "tag": f"in_{idx}",
                "port": XRAY_PORT_BASE + idx,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {"enabled": False},
            }
        )
        outbounds.append(outbound)
        rules.append(
            {
                "type": "field",
                "inboundTag": [f"in_{idx}"],
                "outboundTag": f"out_{idx}",
            }
        )
        valid.append((idx, node))

    if not valid:
        return []

    config = {
        "log": {"loglevel": "none"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        cfg_path = os.path.join(tmpdir, "xray.json")
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f)

        proc = await asyncio.create_subprocess_exec(
            binary,
            "run",
            "-c",
            cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        crashed = False
        results: List[Optional[NodeInfo]] = []
        try:
            ready = await _wait_for_xray_ready(
                proc, XRAY_PORT_BASE + valid[0][0]
            )
            if ready:
                results = list(
                    await asyncio.gather(
                        *(_probe_xray_port(idx, node) for idx, node in valid)
                    )
                )
            if not ready or (
                getattr(proc, "returncode", None) is not None
                and not any(results)
            ):
                crashed = True
                detail = await _read_xray_error(proc)
                print(
                    "[warn] Xray batch exited early "
                    f"(code={getattr(proc, 'returncode', None)}): {detail}"
                )
                results = []
        finally:
            try:
                proc.terminate()
            except (ProcessLookupError, OSError):
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await proc.wait()
                except Exception:
                    pass

    if crashed:
        if _depth == 0 and len(batch) > 1:
            mid = len(batch) // 2
            left = await _run_xray_batch(binary, batch[:mid], _depth=1)
            right = await _run_xray_batch(binary, batch[mid:], _depth=1)
            return left + right
        # Fail open: keep socket-verified nodes when Xray cannot run this batch.
        return list(batch)

    return [node for node in results if node is not None]


def _merge_xray_backfill(
    verified: List[NodeInfo],
    passthrough: List[NodeInfo],
    pool: List[NodeInfo],
) -> List[NodeInfo]:
    """Per-country merge: tunnel-verified nodes first, sockets as backfill.

    Dropping the socket-verified tail globally was the reason eight countries
    showed up as ``0/5 EMPTY``; keeping it per country means a country with
    zero tunnel survivors still fills its quota.
    """
    verified_by_country: Dict[str, List[NodeInfo]] = {}
    for node in verified:
        verified_by_country.setdefault(node.country_code or "", []).append(node)

    backfill_by_country: Dict[str, List[NodeInfo]] = {}
    for node in pool:
        if node.xray_verified:
            continue
        backfill_by_country.setdefault(node.country_code or "", []).append(node)

    merged: List[NodeInfo] = []
    codes = sorted(set(verified_by_country) | set(backfill_by_country))
    for code in codes:
        merged.extend(
            sorted(verified_by_country.get(code, []), key=_effective_sort_key)
        )
        merged.extend(
            sorted(backfill_by_country.get(code, []), key=_effective_sort_key)
        )
    merged.extend(passthrough)
    return merged


async def verify_nodes_with_xray(
    nodes: List[NodeInfo],
    xray_bin: Optional[str] = None,
    keep_unverified_backfill: bool = True,
) -> List[NodeInfo]:
    """Mark real tunnel survivors and keep socket-verified nodes as backfill.

    A node that answers ``generate_204`` through Xray gets ``xray_verified``
    set, which ranks it ahead of every socket-only node; the socket-verified
    nodes stay in the pool so no country can end up without slots.

    Absent the binary (local runs, unit tests) the socket-verified list is
    returned unchanged, so the collector still works without Xray installed.
    """
    if not nodes:
        return nodes

    binary = xray_bin or os.environ.get("XRAY_BIN") or shutil.which("xray")
    if not binary:
        print(
            "[info] Xray binary not found; keeping socket-verified nodes "
            "without tunnel check"
        )
        return nodes

    candidates, passthrough = _xray_candidates(nodes)
    if not candidates:
        return nodes

    survivors: List[NodeInfo] = []
    passed_count = 0
    ran_batches = 0
    for start in range(0, len(candidates), XRAY_BATCH_SIZE):
        batch = candidates[start:start + XRAY_BATCH_SIZE]
        try:
            batch_passed = await _run_xray_batch(binary, batch)
        except Exception as exc:
            # A broken binary/config must never empty the subscription.
            print(f"[warn] Xray batch failed: {exc}")
            ran_batches += 1
            continue
        ran_batches += 1
        for node in batch_passed:
            node.xray_verified = True
        passed_count += len(batch_passed)
        survivors.extend(batch_passed)

    if ran_batches == 0:
        print("[warn] Xray could not run; falling back to socket-verified nodes")
        return nodes

    print(
        f"[info] Xray tunnel check: {passed_count}/{len(candidates)} "
        "candidate(s) passed generate_204"
    )
    if not keep_unverified_backfill or MIN_XRAY_VERIFIED_NODES == 0:
        # Strict mode (used by tests that assert exact 204 filtering).
        return survivors + passthrough
    if passed_count == 0:
        print(
            "[warn] No tunnel-verified node(s); keeping the socket-verified set "
            "so the subscription never collapses"
        )
        return nodes
    return _merge_xray_backfill(survivors, passthrough, nodes)


# ---------------------------------------------------------------------------
# OpenRay streak / carrier telemetry (output/check_counts.json)
# ---------------------------------------------------------------------------


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _telemetry_host_port(link_key: str) -> Optional[Tuple[str, int]]:
    """``(host.lower(), port)`` identity for a telemetry entry key."""
    key = (link_key or "").strip()
    if not key:
        return None
    if "://" in key:
        node = parse_node_info(key)
        if node is None:
            return None
        return (node.host.lower(), node.port)
    host, _sep, port_str = key.rpartition(":")
    try:
        port = int(port_str)
    except (TypeError, ValueError):
        return None
    host = host.strip().strip("[]").lower()
    if not host or not (1 <= port <= 65535):
        return None
    return (host, port)


def parse_openray_check_counts(
    raw_json: str,
) -> Dict[Tuple[str, int], Dict[str, Any]]:
    """Index ``check_counts.json`` by ``(host, port)``. Never raises."""
    try:
        data = json.loads(raw_json)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}

    index: Dict[Tuple[str, int], Dict[str, Any]] = {}
    for link_key, stats in data.items():
        if not isinstance(stats, dict):
            continue
        endpoint = _telemetry_host_port(str(link_key))
        if endpoint is None:
            continue
        iran = stats.get("iran")
        if not isinstance(iran, dict):
            iran = {}
        operators = iran.get("operators")
        if not isinstance(operators, dict):
            operators = {}
        hits = {str(k).lower() for k, v in operators.items() if _as_int(v) > 0}

        entry = index.setdefault(
            endpoint, {"global_streak": 0, "iran_streak": 0, "operators": set()}
        )
        entry["global_streak"] = max(
            entry["global_streak"], _as_int(stats.get("global"))
        )
        entry["iran_streak"] = max(entry["iran_streak"], _as_int(iran.get("total")))
        entry["operators"].update(hits)
    return index


def apply_openray_telemetry(
    nodes: List[NodeInfo],
    telemetry_index: Dict[Tuple[str, int], Dict[str, Any]],
) -> int:
    """Enrich *nodes* in place; returns how many matched the telemetry."""
    if not nodes or not telemetry_index:
        return 0

    matched = 0
    for node in nodes:
        stats = telemetry_index.get((node.host.lower(), node.port))
        if stats is None and node.resolved_ip:
            stats = telemetry_index.get((node.resolved_ip.lower(), node.port))
        if stats is None:
            continue
        matched += 1
        node.global_streak = max(
            node.global_streak, _as_int(stats.get("global_streak"))
        )
        node.iran_streak = max(
            node.iran_streak, _as_int(stats.get("iran_streak"))
        )
        operators = {op for op in (stats.get("operators") or ()) if op}
        if node.iran_streak > 0 or operators:
            node.iran_verified = True
        node.operator_tags.update(operators)
    return matched


async def fetch_openray_telemetry(
    session: aiohttp.ClientSession,
) -> Dict[Tuple[str, int], Dict[str, Any]]:
    """Fetch OpenRay's streak telemetry once; fail-open on any error."""
    for url in OPENRAY_CHECK_COUNTS_URLS:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=OPENRAY_TELEMETRY_TIMEOUT),
            ) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text(errors="replace")
        except Exception as exc:
            print(f"[fetch] ERROR {url}: {exc}")
            continue
        index = parse_openray_check_counts(text)
        if index:
            print(f"[info] OpenRay telemetry: {len(index)} endpoint(s) parsed")
            return index
    return {}


# ---------------------------------------------------------------------------
# Clean node renaming
# ---------------------------------------------------------------------------


def build_clean_name(
    country_code: str, index: int, protocol: str, avg_latency_ms: int
) -> str:
    flag, name = ALLOWED_COUNTRIES[country_code]
    return f"{flag} {name} {index:02d} | {protocol.upper()} | ⚡ {avg_latency_ms}ms | BrickVPN"


# ---------------------------------------------------------------------------
# Iran DPI link shaping: fp=chrome + Cloudflare clean-IP substitution
# ---------------------------------------------------------------------------

SHAPE_CF_NETWORKS = ("ws", "grpc", "http", "h2", "httpupgrade")


def _query_keys(query: str) -> Set[str]:
    return {p.split("=", 1)[0] for p in query.split("&") if p}


def _link_query(link: str) -> str:
    """Raw query string of a share link (fragment stripped)."""
    if "://" not in link:
        return ""
    rest = link.split("://", 1)[1].split("#", 1)[0]
    return rest.split("?", 1)[1] if "?" in rest else ""


def _query_value(query: str, key: str) -> str:
    for part in query.split("&"):
        name, _, value = part.partition("=")
        if name == key:
            return value
    return ""


def _set_query_params(query: str, values: Dict[str, str]) -> str:
    """Set or append query parameters while preserving the original order."""
    parts = [p for p in query.split("&") if p]
    remaining = dict(values)
    out: List[str] = []
    for part in parts:
        key = part.split("=", 1)[0]
        if key in remaining:
            out.append(f"{key}={remaining.pop(key)}")
        else:
            out.append(part)
    out.extend(f"{k}={v}" for k, v in remaining.items())
    return "&".join(out)


def _replace_authority_host(authority: str, new_host: str) -> str:
    """Swap the host of ``userinfo@host:port``, keeping both ends intact."""
    userinfo, sep, hostport = authority.rpartition("@")
    prefix = f"{userinfo}{sep}"
    if hostport.startswith("["):
        end = hostport.find("]")
        port = hostport[end + 1:] if end != -1 else ""
    elif ":" in hostport:
        port = ":" + hostport.rsplit(":", 1)[1]
    else:
        port = ""
    return f"{prefix}{new_host}{port}"


def _shape_uri_link(
    link: str,
    new_host: Optional[str] = None,
    params: Optional[Dict[str, str]] = None,
    ensure_fp: bool = False,
    drop_params: Sequence[str] = (),
) -> str:
    """Rewrite a vless:// or trojan:// link in place (param order preserved)."""
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return link

    fragment = ""
    if "#" in rest:
        rest, fragment = rest.split("#", 1)
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)

    if new_host:
        rest = _replace_authority_host(rest, new_host)

    drop = {name.lower() for name in drop_params}
    if drop:
        query = "&".join(
            p
            for p in query.split("&")
            if p and p.split("=", 1)[0].lower() not in drop
        )

    update = dict(params or {})
    if ensure_fp and _query_value(query, "fp").strip().lower() not in PQC_SAFE_FINGERPRINTS:
        # fp=edge/ios/qq/random do not send X25519MLKEM768 and REALITY rejects them.
        update["fp"] = "chrome"
    query = _set_query_params(query, update)

    shaped = f"{scheme}://{rest}"
    if query:
        shaped += "?" + query
    if fragment:
        shaped += "#" + fragment
    return shaped


def _shape_vmess_link(
    link: str,
    new_host: Optional[str] = None,
    domain_sni: str = "",
    ensure_fp: bool = False,
) -> str:
    """Rewrite a vmess:// JSON config (connect address / sni / host / fp)."""
    b64 = link[len("vmess://"):].split("#", 1)[0]
    pad = len(b64) % 4
    if pad:
        b64 += "=" * (4 - pad)
    try:
        cfg = json.loads(
            base64.b64decode(b64).decode("utf-8", errors="replace")
        )
    except Exception:
        return link
    if not isinstance(cfg, dict):
        return link

    # Corrupted ECH material (or plain-UDP ECH lookups) must never ship, and
    # Xray 26.9.9 no longer has allowInsecure at all.
    for dead_key in (
        "ech",
        "echConfigList",
        "allowInsecure",
        "allow_insecure",
        "insecure",
        "verify_cert",
    ):
        cfg.pop(dead_key, None)

    if new_host:
        cfg["add"] = new_host
    if domain_sni:
        cfg["sni"] = cfg.get("sni") or domain_sni
        cfg["host"] = cfg.get("host") or domain_sni
    if ensure_fp:
        current_fp = str(cfg.get("fp", "")).strip().lower()
        if current_fp not in PQC_SAFE_FINGERPRINTS:
            cfg["fp"] = "chrome"

    new_b64 = base64.b64encode(
        json.dumps(cfg, separators=(",", ":"), ensure_ascii=False).encode()
    ).decode()
    return "vmess://" + new_b64


def shape_node_for_iran(
    node: NodeInfo,
    index: int = 1,
    clean_ips: Optional[Sequence[str]] = None,
    link: Optional[str] = None,
) -> str:
    """Shape one link for Iranian DPI.

    * TLS links always carry ``fp=chrome`` so DPI does not fingerprint the
      default Go/OpenSSL handshake.
    * Cloudflare CDN nodes whose connect address sits inside a blocked edge
      range (``188.114.96.0/20``) are re-pointed at a CIDR-verified clean IP,
      while ``sni``/``host`` keep the camouflage domain untouched.
    """
    source = link if link is not None else (node.original_link or node.raw_link)
    base = _clean_link(source or "")
    if not base or not node.tls_enabled:
        return base

    requested = list(clean_ips) if clean_ips is not None else list(DEFAULT_CF_CLEAN_IPS)
    pool = [str(ip).strip() for ip in requested if is_safe_cloudflare_clean_ip(str(ip))]
    if not pool:
        # Never trust an unverified override; fall back to the known-good pool.
        pool = [ip for ip in DEFAULT_CF_CLEAN_IPS if is_safe_cloudflare_clean_ip(ip)]
    if not pool:
        pool = list(DEFAULT_CF_CLEAN_IPS)

    domain_sni = ""
    if node.sni and not _is_ip_literal(node.sni):
        domain_sni = node.sni.strip()
    elif node.host and not _is_ip_literal(node.host):
        domain_sni = node.host.strip()

    is_blocked_cf = is_blocked_cloudflare_ip(
        node.resolved_ip
    ) or is_blocked_cloudflare_ip(node.host)
    should_replace_cf_ip = (
        is_blocked_cf
        and (node.network or "").lower() in SHAPE_CF_NETWORKS
        and bool(domain_sni)
    )
    new_host = (
        pool[(max(index, 1) - 1) % len(pool)] if should_replace_cf_ip else None
    )

    if node.protocol == "vmess":
        return _shape_vmess_link(
            base,
            new_host=new_host,
            domain_sni=domain_sni if should_replace_cf_ip else "",
            ensure_fp=True,
        )

    if node.protocol not in ("vless", "trojan"):
        return base

    params: Dict[str, str] = {}
    if should_replace_cf_ip:
        params["sni"] = domain_sni
        if (node.network or "").lower() in ("ws", "http", "h2", "httpupgrade"):
            params["host"] = domain_sni
    # Aggregators export REALITY keys in mixed base64 spellings; publishing the
    # canonical unpadded base64url form keeps Xray from exiting with code 23.
    if (node.security or "").lower() == "reality":
        clean_pbk = normalize_reality_pbk(_query_value(_link_query(base), "pbk"))
        if clean_pbk:
            params["pbk"] = clean_pbk
    return _shape_uri_link(
        base,
        new_host=new_host,
        params=params,
        ensure_fp=True,
        drop_params=("ech", "allowInsecure", "allow_insecure", "insecure"),
    )


def rename_node(node: NodeInfo, country_code: str, index: int) -> str:
    if not node.avg_latency_ms:
        node.avg_latency_ms = 0
    clean = build_clean_name(
        country_code, index, node.protocol, int(node.avg_latency_ms)
    )
    node.clean_name = clean

    base_link = node.original_link
    if node.protocol == "vmess":
        b64 = node.original_link[len("vmess://"):].split("#", 1)[0]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        try:
            cfg = json.loads(
                base64.b64decode(b64).decode("utf-8", errors="replace")
            )
            if isinstance(cfg, dict):
                cfg["ps"] = clean
                new_b64 = base64.b64encode(
                    json.dumps(cfg, separators=(",", ":"), ensure_ascii=False).encode()
                ).decode()
                base_link = "vmess://" + new_b64
        except Exception:
            base_link = node.original_link
    else:
        base = node.original_link.split("#", 1)[0]
        base_link = f"{base}#{clean}"

    # fp=chrome / clean-IP shaping is applied last so it also covers the
    # freshly generated remark fragment.
    node.renamed_link = shape_node_for_iran(node, index, link=base_link)
    return node.renamed_link


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _ensure_dirs() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRIES_DIR, exist_ok=True)
    os.makedirs(PROTOCOLS_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "operators"), exist_ok=True)


def _write_plain(path: str, links: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(links))
        if links:
            f.write("\n")


def _write_b64(path: str, links: List[str]) -> None:
    plain = "\n".join(links)
    if links:
        plain += "\n"
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    with open(path, "w", encoding="ascii") as f:
        f.write(encoded)


# ---------------------------------------------------------------------------
# Xray 26+ FinalMask (fm=) subscription shaping
# ---------------------------------------------------------------------------


def build_xray_finalmask_json(security: str) -> str:
    """FinalMask JSON for Xray 26+ TLS fragmentation.

    Per 2dust/v2rayN#10407 and v2rayNG@58dbb71: REALITY breaks with
    ``packets="tlshello"`` on Xray 26+, so REALITY MUST use ``packets="1-3"``.
    Standard TLS uses ``packets="tlshello"``.
    """
    packets_mode = "1-3" if (security or "").lower() == "reality" else "tlshello"
    mask_obj = {
        "tcp": [
            {
                "type": "fragment",
                "settings": {
                    "packets": packets_mode,
                    "length": "10-30",
                    "delay": "5-10",
                },
            }
        ]
    }
    return json.dumps(mask_obj, separators=(",", ":"))


def inject_xray_finalmask_fm(uri: str, security: str = "") -> str:
    """Append/replace ``fm=<FinalMask JSON>`` on a vless/trojan URI.

    Unfragmented ClientHellos get a DPI ``TCP RST`` on MCI/Irancell, so Xray 26+
    clients need the mask to fragment packets 1-3 (REALITY) or the TLS hello.
    """
    text = (uri or "").strip()
    if not text:
        return uri
    lowered = text.lower()
    if not (lowered.startswith("vless://") or lowered.startswith("trojan://")):
        return uri

    sec = (
        security or ("reality" if "security=reality" in lowered else "tls")
    ).lower()
    encoded = quote(build_xray_finalmask_json(sec), safe="")
    return _shape_uri_link(text, params={"fm": encoded})


# ---------------------------------------------------------------------------
# Encrypted subscription (enc:v1:, AES-256-GCM)
# ---------------------------------------------------------------------------

SUB_ENC_PREFIX = "enc:v1:"
SUB_ENC_FILENAME = "sub_enc.txt"
AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16


def parse_aes_key(raw_key: str) -> bytes:
    """Parse a 64-char hex or base64 encoded 32-byte AES-256 key."""
    raw = (raw_key or "").strip()
    if not raw:
        raise ValueError("empty AES key")
    key: Optional[bytes] = None
    if len(raw) == 64:
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            key = None
    if key is None:
        try:
            key = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise ValueError("AES key is neither hex nor base64") from exc
    if len(key) != AES_KEY_BYTES:
        raise ValueError("AES-256 key must decode to exactly 32 bytes")
    return key


def encrypt_subscription_payload(plaintext: str, key_bytes: bytes) -> str:
    """Encrypt *plaintext* into ``enc:v1:<base64(nonce + ct + tag)>``."""
    if AESGCM is None:
        raise RuntimeError("cryptography is required for encrypted subscriptions")
    if len(key_bytes) != AES_KEY_BYTES:
        raise ValueError("AES-256 key must be exactly 32 bytes")
    nonce = os.urandom(GCM_NONCE_BYTES)
    sealed = AESGCM(key_bytes).encrypt(nonce, plaintext.encode("utf-8"), None)
    return SUB_ENC_PREFIX + base64.b64encode(nonce + sealed).decode("ascii")


def decrypt_subscription_payload(token: str, key_bytes: bytes) -> str:
    """Reverse :func:`encrypt_subscription_payload` (authenticated)."""
    if AESGCM is None:
        raise RuntimeError("cryptography is required for encrypted subscriptions")
    text = (token or "").strip()
    if not text.startswith(SUB_ENC_PREFIX):
        raise ValueError("missing enc:v1: prefix")
    blob = base64.b64decode(text[len(SUB_ENC_PREFIX):], validate=True)
    if len(blob) < GCM_NONCE_BYTES + GCM_TAG_BYTES:
        raise ValueError("encrypted payload is truncated")
    nonce = blob[:GCM_NONCE_BYTES]
    sealed = blob[GCM_NONCE_BYTES:]
    return AESGCM(key_bytes).decrypt(nonce, sealed, None).decode("utf-8")


def _write_encrypted_sub(plaintext: str) -> bool:
    """Write ``sub_enc.txt`` when ``BRICK_SUB_AES_KEY`` is configured."""
    path = os.path.join(OUTPUT_DIR, SUB_ENC_FILENAME)
    raw_key = os.environ.get("BRICK_SUB_AES_KEY", "").strip()
    if not raw_key:
        # Never publish a stale encrypted mirror from an earlier run.
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass
        return False
    try:
        key_bytes = parse_aes_key(raw_key)
        token = encrypt_subscription_payload(plaintext, key_bytes)
    except (ValueError, RuntimeError) as exc:
        print(f"[warn] Encrypted subscription skipped: {exc}")
        return False
    with open(path, "w", encoding="ascii") as f:
        f.write(token)
        f.write("\n")
    return True


def _operator_candidates(by_protocol: Dict[str, List[NodeInfo]]) -> List[NodeInfo]:
    """Every tested node once, best-ranked first (input for operator subs)."""
    pool: List[NodeInfo] = []
    seen: Set[int] = set()
    for proto in PROXY_SCHEMES:
        for node in by_protocol.get(proto, []):
            if id(node) in seen:
                continue
            seen.add(id(node))
            pool.append(node)
    pool.sort(
        key=lambda n: n.quality_score
        if n.quality_score is not None
        else float("inf")
    )
    return pool


def _write_operator_outputs(
    by_protocol: Dict[str, List[NodeInfo]], operators_dir: str
) -> Dict[str, Any]:
    """Write operator-scoped subscriptions (mci / irancell / tci).

    Tagged nodes come first, then other Iran-verified nodes, then the rest of
    the eligible pool, so a thin operator feed is backfilled instead of empty.
    """
    eligible = [n for n in _operator_candidates(by_protocol) if is_main_pool_eligible(n)]
    report: Dict[str, Any] = {}
    for op in OPERATOR_TAGS:
        tagged = [n for n in eligible if op in n.operator_tags]
        tagged_ids = {id(n) for n in tagged}
        iran_fill = [
            n for n in eligible if id(n) not in tagged_ids and n.iran_verified
        ]
        filled_ids = tagged_ids | {id(n) for n in iran_fill}
        rest = [n for n in eligible if id(n) not in filled_ids]
        picked = select_diverse_top_nodes(
            tagged + iran_fill + rest, OPERATOR_QUOTA
        )
        links = [
            rename_node(n, n.country_code or "DE", idx)
            for idx, n in enumerate(picked, start=1)
        ]
        _write_plain(os.path.join(operators_dir, f"{op}.txt"), links)
        _write_b64(os.path.join(operators_dir, f"{op}_base64.txt"), links)
        report[op] = {"count": len(links), "quota": OPERATOR_QUOTA}
    return report


def write_all_outputs(
    by_country: Dict[str, List[NodeInfo]],
    by_protocol: Dict[str, List[NodeInfo]],
    total_tested: int = 0,
    total_passed: int = 0,
) -> Dict[str, Any]:
    _ensure_dirs()

    operators_dir = os.path.join(OUTPUT_DIR, "operators")
    os.makedirs(operators_dir, exist_ok=True)

    # servers.txt / sub.txt: each country numbered independently 01..05.
    # Only encrypted, sing-box compatible nodes compete for the main pool.
    main_links: List[str] = []
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        nodes = [
            n for n in by_country.get(code, []) if is_main_pool_eligible(n)
        ]
        selected = select_diverse_top_nodes(nodes, MAIN_QUOTA_PER_COUNTRY)
        for idx, n in enumerate(selected, start=1):
            main_links.append(rename_node(n, code, idx))

    _write_plain(SERVERS_FILE, main_links)
    _write_b64(SUB_FILE, main_links)

    # Xray 26+ FinalMask (fm=) mirrors for v2rayN / v2rayNG. Only vless:// and
    # trojan:// links can carry fm=, so vmess slots are replaced by the next
    # eligible vless/trojan node of the same country. servers.txt itself stays
    # clean for sing-box / mihomo, which do not understand fm=.
    xray_frag_lines: List[str] = []
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        candidates = [
            n
            for n in by_country.get(code, [])
            if is_main_pool_eligible(n) and n.protocol in ("vless", "trojan")
        ]
        picked = select_diverse_top_nodes(candidates, MAIN_QUOTA_PER_COUNTRY)
        for idx, n in enumerate(picked, start=1):
            xray_frag_lines.append(
                inject_xray_finalmask_fm(rename_node(n, code, idx))
            )
    _write_plain(
        os.path.join(OUTPUT_DIR, "servers_xray_frag.txt"), xray_frag_lines
    )
    _write_b64(os.path.join(OUTPUT_DIR, "sub_xray_frag.txt"), xray_frag_lines)

    # Optional AES-256-GCM protected mirror of servers.txt (enc:v1: payload).
    plain_main = "\n".join(main_links)
    if main_links:
        plain_main += "\n"
    encrypted_sub = _write_encrypted_sub(plain_main)

    country_report: Dict[str, Any] = {}
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        nodes = [
            n for n in by_country.get(code, []) if is_main_pool_eligible(n)
        ]
        # countries/{CODE}.txt: numbered independently 01..20 per country.
        top_nodes = dedupe_by_pure_ip(nodes)[:COUNTRY_FILE_QUOTA]
        country_links = [
            rename_node(n, code, idx) for idx, n in enumerate(top_nodes, start=1)
        ]
        flag, name = ALLOWED_COUNTRIES[code]
        count = len(nodes)

        avg_latency: Optional[int] = None
        if nodes:
            latencies = [
                n.avg_latency_ms for n in nodes if n.avg_latency_ms is not None
            ]
            if latencies:
                avg_latency = round(sum(latencies) / len(latencies))

        if count == 0:
            status = "empty"
        elif count < MAIN_QUOTA_PER_COUNTRY:
            status = "low"
        else:
            status = "healthy"

        country_report[code] = {
            "count": count,
            "quota": MAIN_QUOTA_PER_COUNTRY,
            "status": status,
            "avg_latency_ms": avg_latency,
            "country_name": name,
            "flag": flag,
        }

        cpath = os.path.join(COUNTRIES_DIR, f"{code}.txt")
        cbpath = os.path.join(COUNTRIES_DIR, f"{code}_base64.txt")
        _write_plain(cpath, country_links)
        _write_b64(cbpath, country_links)

    for proto in PROXY_SCHEMES:
        nodes = by_protocol.get(proto, [])
        proto_links = [
            rename_node(n, n.country_code or "DE", idx)
            for idx, n in enumerate(nodes, start=1)
        ]
        ppath = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        pbpath = os.path.join(PROTOCOLS_DIR, f"{proto}_base64.txt")
        _write_plain(ppath, proto_links)
        _write_b64(pbpath, proto_links)

    main_count = len(main_links)

    operator_report = _write_operator_outputs(by_protocol, operators_dir)

    alerts = [
        code for code, rep in country_report.items() if rep["status"] == "empty"
    ]

    report = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tested": total_tested,
        "total_passed": total_passed,
        "main_sub_count": main_count,
        "encrypted_sub": encrypted_sub,
        "countries": country_report,
        "operators": operator_report,
        "alerts": alerts,
    }
    with open(STATUS_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return report


# ---------------------------------------------------------------------------
# GitHub Actions annotations & step summary
# ---------------------------------------------------------------------------


def emit_annotations(country_report: Dict[str, Any]) -> None:
    if os.environ.get("GITHUB_ACTIONS") != "true":
        return
    for code, rep in country_report.items():
        flag, name = ALLOWED_COUNTRIES[code]
        count = rep["count"]
        if count == 0:
            print(
                f"::error title=🚨 Country Empty ({code})::"
                f"{name} ({code}) has 0/5 working servers!"
            )
        elif count < MAIN_QUOTA_PER_COUNTRY:
            print(
                f"::warning title=⚠️ Country Low ({code})::"
                f"{name} ({code}) only has {count}/5 working servers."
            )


def write_step_summary(country_report: Dict[str, Any]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return

    lines: List[str] = []
    lines.append("# 📊 BrickVPN Subscription Health Dashboard")
    lines.append("")
    lines.append("| Country | Flag | Active / 5 | Avg Latency | Health |")
    lines.append("|---------|------|------------|-------------|--------|")

    for code in sorted(ALLOWED_COUNTRIES.keys()):
        rep = country_report.get(code, {"count": 0, "avg_latency_ms": None})
        flag, name = ALLOWED_COUNTRIES[code]
        count = rep["count"]
        avg = rep["avg_latency_ms"]
        avg_str = f"{avg}ms" if avg is not None else "—"
        if rep["status"] == "healthy":
            badge = "✅ Full"
        elif rep["status"] == "low":
            badge = "⚠️ Low"
        else:
            badge = "🚨 EMPTY"
        lines.append(f"| {name} | {flag} | {count} / 5 | {avg_str} | {badge} |")

    lines.append("")
    lines.append(
        f"**Total passed:** {sum(r['count'] for r in country_report.values())} nodes"
    )
    lines.append("")

    with open(path, "a", encoding="utf-8") as f:
        f.write("\n".join(lines))
        f.write("\n")


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------


def load_sources() -> List[str]:
    if not os.path.exists(SOURCES_FILE):
        print(f"[error] {SOURCES_FILE} not found.", file=sys.stderr)
        return []
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        sources = []
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            sources.append(line)
        return sources


async def main() -> int:
    try:
        return await _main_impl()
    except Exception as exc:
        print(f"[fatal] Unexpected error: {exc}", file=sys.stderr)
        # Still write empty outputs so the workflow doesn't break downstream
        try:
            write_all_outputs({}, {}, 0, 0)
        except Exception:
            pass
        return 0


async def _main_impl() -> int:
    started = time.monotonic()
    mark_at = started

    def _mark(label: str) -> None:
        nonlocal mark_at
        now = time.monotonic()
        print(f"[time] {label}: {now - mark_at:.1f}s")
        mark_at = now

    # getaddrinfo runs in the loop's default executor, so give it enough worker
    # threads to keep the DNS semaphore busy during the resolution stage.
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DNS, thread_name_prefix="dns")
    )

    urls = load_sources()
    if not urls:
        print("[info] No source URLs found in sources.txt.")
        write_all_outputs({}, {}, 0, 0)
        return 0

    print(f"[info] Fetching {len(urls)} source URL(s) ...")
    pages = await fetch_all(urls)
    _mark("fetch")

    # --- Stage 1+2: extract links, parse, tag provenance, dedup (host,port)
    parsed: List[NodeInfo] = []
    by_key: Dict[Tuple[str, int], NodeInfo] = {}
    total_extracted = 0
    for url, text in zip(urls, pages):
        if not text:
            continue
        iran_ok, tags = classify_source_url(url)
        links = extract_links(text)
        total_extracted += len(links)
        print(f"[info] {url}: extracted {len(links)} link(s)")
        for link in links:
            node = parse_node_info(link)
            if node is None:
                continue
            node.iran_verified = iran_ok
            node.operator_tags = set(tags)
            existing = by_key.get(node.key)
            if existing is not None:
                _merge_provenance(existing, node)
                continue
            by_key[node.key] = node
            parsed.append(node)

    print(f"[info] Total extracted: {total_extracted} link(s)")
    print(f"[info] After parse + dedup: {len(parsed)} node(s)")
    _mark("parse")

    # --- Stage 3: DNS resolution + IP:Port deduplication ------------------
    parsed = await resolve_and_dedup_nodes(parsed)
    print(f"[info] After DNS + IP:Port dedup: {len(parsed)} node(s)")
    _mark("dns")

    connector = aiohttp.TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        # --- Stage 3b: OpenRay streak/carrier telemetry (fail-open) --------
        if parsed:
            telemetry = await fetch_openray_telemetry(session)
            if telemetry:
                enriched = apply_openray_telemetry(parsed, telemetry)
                print(f"[info] OpenRay telemetry matched {enriched} node(s)")

        # --- Stage 4: GeoIP pre-filter (offline .mmdb = microseconds) ------
        # Filtering by country BEFORE probing keeps network work limited to the
        # 10 target countries instead of thousands of unrelated nodes.
        mmdb_ready = await ensure_mmdb_database(session)
        if mmdb_ready:
            candidates = await filter_by_geoip(
                session, parsed, api_fallback_limit=GEOIP_API_FALLBACK_LIMIT
            )
            print(f"[info] After GeoIP (allowed countries): {len(candidates)} node(s)")
            _mark("geoip pre-filter")
        else:
            candidates = parsed

        # --- Stage 5: Dual-probe stability + payload/TTFB verification -----
        sem = asyncio.Semaphore(MAX_CONCURRENT_PROBES)

        async def _probe(node: NodeInfo) -> None:
            async with sem:
                await verify_node_stability(node)

        await asyncio.gather(*(_probe(n) for n in candidates))

        passed = [n for n in candidates if n.quality_score is not None]
        print(f"[info] After dual-probe stability: {len(passed)} node(s)")
        _mark("probe")

        # --- Stage 5b: optional Xray tunnel verification (OFF by default) ---
        # The OpenRay inside-Iran feeds are already tunnel-checked upstream, and
        # batching them through Xray rejected whole VLESS/REALITY batches (17-24
        # survivors instead of ~700). The socket probes above are the production
        # gate; the Xray stage stays available as an explicit opt-in.
        if os.environ.get("BRICK_ENABLE_XRAY_STAGE") == "1":
            tunnel_checked = await verify_nodes_with_xray(passed)
            if tunnel_checked:
                passed = tunnel_checked
                print(f"[info] After Xray tunnel check: {len(passed)} node(s)")
            else:
                print("[warn] Xray tunnel check produced no nodes; keeping stable set")
        else:
            print("[info] Xray tunnel stage disabled (BRICK_ENABLE_XRAY_STAGE != 1)")
        _mark("xray tunnel")

        # --- Stage 6: GeoIP filtering (only when the offline DB was unusable)
        if mmdb_ready:
            allowed = passed
        else:
            allowed = await filter_by_geoip(session, passed)
            print(f"[info] After GeoIP (allowed countries): {len(allowed)} node(s)")

    # --- Stage 7: Group by country, sort by quality, one node per IP ------
    by_country: Dict[str, List[NodeInfo]] = {code: [] for code in ALLOWED_COUNTRIES}
    by_protocol: Dict[str, List[NodeInfo]] = {proto: [] for proto in PROXY_SCHEMES}

    for n in allowed:
        cc = n.country_code
        if cc and cc in by_country:
            by_country[cc].append(n)
        by_protocol[n.protocol].append(n)

    for code, nodes in by_country.items():
        nodes.sort(key=lambda n: (n.quality_score or float("inf")))
        by_country[code] = dedupe_by_pure_ip(nodes)

    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda n: (n.quality_score or float("inf")))

    # --- Stage 8: Write outputs (every list is numbered independently) ----
    report = write_all_outputs(
        by_country,
        by_protocol,
        total_tested=len(candidates),
        total_passed=len(allowed),
    )

    # --- Stage 11: GitHub Actions annotations + summary -------------------
    emit_annotations(report["countries"])
    write_step_summary(report["countries"])

    print(f"[info] Total passed: {report['total_passed']}")
    print(f"[info] Main sub count: {report['main_sub_count']}")
    print(f"[info] Alerts (empty countries): {report['alerts']}")
    print(f"[info] Wrote outputs to {OUTPUT_DIR}/")
    _mark("output")
    print(f"[time] total: {time.monotonic() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))



