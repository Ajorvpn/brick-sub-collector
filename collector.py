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
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs

import aiohttp

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
MAX_LATENCY_MS = 500
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

MAIN_QUOTA_PER_COUNTRY = 5
COUNTRY_FILE_QUOTA = 20

PROXY_SCHEMES = ("vless", "vmess", "trojan", "ss")

# Service/OS ports that must never be probed as proxy endpoints.
BLOCKED_PORTS: Set[int] = {
    21, 22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 445,
    1433, 3306, 3389, 5432, 6379, 27017,
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

    resolved_ip: Optional[str] = None
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    latency_1: Optional[float] = None
    latency_2: Optional[float] = None
    avg_latency_ms: Optional[int] = None
    jitter_ms: Optional[int] = None
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
        host = str(cfg.get("add", "")).strip()
        port_raw = cfg.get("port", 0)
        try:
            port = int(port_raw)
        except (TypeError, ValueError):
            return None
        if not host or not _port_allowed(port):
            return None
        node.host = host
        node.port = port
        node.network = str(cfg.get("net", "tcp")).lower()
        node.tls_enabled = str(cfg.get("tls", "")).lower() == "tls"
        node.sni = cfg.get("sni") or cfg.get("host") or None
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

    if scheme == "trojan":
        node.tls_enabled = True
        node.network = params.get("type", "tcp").lower()
        node.sni = params.get("sni") or params.get("host") or None
    elif scheme == "vless":
        node.tls_enabled = params.get("security", "").lower() in ("tls", "reality")
        node.network = params.get("type", "tcp").lower()
        node.sni = params.get("sni") or params.get("host") or None
    else:
        node.tls_enabled = False
        node.network = "tcp"
        node.sni = None

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

    # Deduplicate by (resolved_ip, port)
    seen_ips: Set[str] = set()
    unique: List[NodeInfo] = []
    for n in public:
        k = n.ip_key
        if k in seen_ips:
            continue
        seen_ips.add(k)
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

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

PAYLOAD_READ_BYTES = 4096
PAYLOAD_REQUEST_TEMPLATE = (
    "GET / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "User-Agent: Mozilla/5.0\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "\r\n"
)


def _build_payload_request(node: NodeInfo) -> bytes:
    """Active HTTP/WebSocket upgrade request used by the payload probe."""
    return PAYLOAD_REQUEST_TEMPLATE.format(host=node.sni or node.host).encode()


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
    node: NodeInfo,
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to the node, completing a full TLS handshake when required.

    Raises on refused/reset connections and TLS failures, and refuses to return
    a TLS transport that negotiated no usable cipher.
    """
    ip = node.resolved_ip
    if not ip:
        raise ConnectionError("node has no resolved IP")

    if not node.tls_enabled:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, node.port), timeout=PROBE_TIMEOUT
        )

    sni = node.sni or node.host
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, node.port, ssl=_SSL_CTX, server_hostname=sni),
        timeout=PROBE_TIMEOUT,
    )
    ssl_object = writer.get_extra_info("ssl_object")
    if ssl_object is None or ssl_object.cipher() is None:
        await _close_writer(writer)
        raise ssl.SSLError("TLS transport negotiated no valid cipher")
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


async def _payload_probe(node: NodeInfo) -> Tuple[bool, int, float]:
    """Probe 2: active payload download / TTFB verification.

    Returns ``(ok, payload_bytes, latency)``. Latency is the connection (and
    TLS handshake) establishment time, replaced by real TTFB when payload
    flows, so healthy-but-silent reality endpoints are not penalised by the
    read wait.

    Strictness:
      * TLS endpoints must handshake with a valid cipher. Payload bytes or a
        clean read timeout pass; EOF, reset and TLS alerts drop the node.
      * Non-TLS vless/vmess/trojan (and ws/http/h2 transports) must answer the
        HTTP probe with payload starting ``HTTP/`` inside PAYLOAD_READ_TIMEOUT.
      * Non-TLS ``ss://`` endpoints receive 32 random bytes; only an immediate
        reset drops them.
    """
    started = time.monotonic()
    try:
        reader, writer = await _open_connection(node)
    except Exception:
        return False, 0, (time.monotonic() - started) * 1000.0

    established_ms = (time.monotonic() - started) * 1000.0

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


def dedupe_by_pure_ip(nodes: List[NodeInfo]) -> List[NodeInfo]:
    """Keep only the best-ranked node per unique IP (input must be sorted)."""
    seen: Set[str] = set()
    unique: List[NodeInfo] = []
    for n in nodes:
        ip = n.pure_ip
        if not ip or ip in seen:
            continue
        seen.add(ip)
        unique.append(n)
    return unique



# ---------------------------------------------------------------------------
# Clean node renaming
# ---------------------------------------------------------------------------


def build_clean_name(
    country_code: str, index: int, protocol: str, avg_latency_ms: int
) -> str:
    flag, name = ALLOWED_COUNTRIES[country_code]
    return f"{flag} {name} {index:02d} | {protocol.upper()} | ⚡ {avg_latency_ms}ms | BrickVPN"


def rename_node(node: NodeInfo, country_code: str, index: int) -> str:
    if not node.avg_latency_ms:
        node.avg_latency_ms = 0
    clean = build_clean_name(
        country_code, index, node.protocol, int(node.avg_latency_ms)
    )
    node.clean_name = clean

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
                node.renamed_link = "vmess://" + new_b64
                return node.renamed_link
        except Exception:
            pass
        node.renamed_link = node.original_link
        return node.renamed_link

    link = node.original_link
    if "#" in link:
        base = link.split("#", 1)[0]
    else:
        base = link
    node.renamed_link = f"{base}#{clean}"
    return node.renamed_link


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


def _ensure_dirs() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRIES_DIR, exist_ok=True)
    os.makedirs(PROTOCOLS_DIR, exist_ok=True)


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


def write_all_outputs(
    by_country: Dict[str, List[NodeInfo]],
    by_protocol: Dict[str, List[NodeInfo]],
    total_tested: int = 0,
    total_passed: int = 0,
) -> Dict[str, Any]:
    _ensure_dirs()

    # servers.txt / sub.txt: each country numbered independently 01..05.
    main_links: List[str] = []
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        nodes = by_country.get(code, [])
        for idx, n in enumerate(nodes[:MAIN_QUOTA_PER_COUNTRY], start=1):
            main_links.append(rename_node(n, code, idx))

    _write_plain(SERVERS_FILE, main_links)
    _write_b64(SUB_FILE, main_links)

    country_report: Dict[str, Any] = {}
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        nodes = by_country.get(code, [])
        # countries/{CODE}.txt: numbered independently 01..20 per country.
        top_nodes = nodes[:COUNTRY_FILE_QUOTA]
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

    alerts = [
        code for code, rep in country_report.items() if rep["status"] == "empty"
    ]

    report = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tested": total_tested,
        "total_passed": total_passed,
        "main_sub_count": main_count,
        "countries": country_report,
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

    # --- Stage 1: Extract links -------------------------------------------
    all_links: List[str] = []
    for url, text in zip(urls, pages):
        if not text:
            continue
        links = extract_links(text)
        print(f"[info] {url}: extracted {len(links)} link(s)")
        all_links.extend(links)

    print(f"[info] Total extracted: {len(all_links)} link(s)")

    # --- Stage 2: Parse + dedup by (host, port) ---------------------------
    parsed: List[NodeInfo] = []
    seen_keys: Set[Tuple[str, int]] = set()
    for link in all_links:
        node = parse_node_info(link)
        if node is None:
            continue
        k = node.key
        if k in seen_keys:
            continue
        seen_keys.add(k)
        parsed.append(node)

    print(f"[info] After parse + dedup: {len(parsed)} node(s)")
    _mark("parse")

    # --- Stage 3: DNS resolution + IP:Port deduplication ------------------
    parsed = await resolve_and_dedup_nodes(parsed)
    print(f"[info] After DNS + IP:Port dedup: {len(parsed)} node(s)")
    _mark("dns")

    connector = aiohttp.TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
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



