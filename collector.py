#!/usr/bin/env python3
"""
BrickVPN Subscription Collector & Tester (Multi-Stage)
======================================================

Reads subscription URLs from ``sources.txt``, fetches them concurrently with
``asyncio`` + ``aiohttp``, extracts proxy share links, runs them through a
multi-stage strict health pipeline:

  1. Deep config parsing (VLESS / VMess / Trojan / SS)
  2. DNS resolution + per-(IP,Port) deduplication
  3. Batch GeoIP filtering (10 allowed top-tier countries only)
  4. Dual-probe stability + real TLS/SNI handshake (2.5s timeout x 2)
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
import json
import os
import re
import socket
import ssl
import sys
import time
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
PROBE_TIMEOUT = 2.5
PROBE_GAP = 0.1
MAX_CONCURRENT_PROBES = 60

MAIN_QUOTA_PER_COUNTRY = 5
COUNTRY_FILE_QUOTA = 20

PROXY_SCHEMES = ("vless", "vmess", "trojan", "ss")

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


def extract_links(text: str) -> List[str]:
    found: List[str] = []
    decoded = try_base64_decode(text)
    candidates = [decoded] if decoded is not None else []
    candidates.append(text)
    for candidate in candidates:
        for m in PROXY_LINK_RE.finditer(candidate):
            link = m.group(0).strip().rstrip('.,;:)]}\'"`>')
            if link:
                found.append(link)
    return found



# ---------------------------------------------------------------------------
# Deep config parsing
# ---------------------------------------------------------------------------


def _extract_query_params(query: str) -> Dict[str, str]:
    if not query:
        return {}
    parsed = parse_qs(query, keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in parsed.items()}


def parse_node_info(link: str) -> Optional[NodeInfo]:
    try:
        scheme, rest = link.split("://", 1)
    except ValueError:
        return None
    scheme = scheme.lower()
    if scheme not in PROXY_SCHEMES:
        return None

    node = NodeInfo(protocol=scheme, original_link=link)

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
        if not host or port <= 0 or port > 65535:
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
    if not host or port <= 0 or port > 65535:
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
# Batch GeoIP filtering (ip-api.com)
# ---------------------------------------------------------------------------


async def batch_geoip(
    session: aiohttp.ClientSession, ips: List[str]
) -> Dict[str, Optional[str]]:
    result: Dict[str, Optional[str]] = {}
    if not ips:
        return result

    payload = [{"query": ip, "fields": "status,countryCode,query"} for ip in ips]
    try:
        async with session.post(
            "http://ip-api.com/batch",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=20.0),
        ) as resp:
            if resp.status != 200:
                return {ip: None for ip in ips}
            data = await resp.json(content_type=None)
    except Exception:
        return {ip: None for ip in ips}

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


async def filter_by_geoip(
    session: aiohttp.ClientSession, nodes: List[NodeInfo]
) -> List[NodeInfo]:
    sem = asyncio.Semaphore(MAX_CONCURRENT_PROBES)

    async def _resolve(node: NodeInfo) -> None:
        async with sem:
            ip = await resolve_hostname(node.host)
            node.resolved_ip = ip

    await asyncio.gather(*(_resolve(n) for n in nodes))

    resolved = [n for n in nodes if n.resolved_ip]

    seen_ips: Set[Tuple[Optional[str], int]] = set()
    unique: List[NodeInfo] = []
    for n in resolved:
        k = n.ip_key
        if k in seen_ips:
            continue
        seen_ips.add(k)
        unique.append(n)

    all_ips = [n.resolved_ip for n in unique if n.resolved_ip]
    ip_to_country: Dict[str, Optional[str]] = {}
    for i in range(0, len(all_ips), GEOIP_CHUNK):
        chunk = all_ips[i : i + GEOIP_CHUNK]
        part = await batch_geoip(session, chunk)
        ip_to_country.update(part)

    allowed: List[NodeInfo] = []
    for n in unique:
        cc = ip_to_country.get(n.resolved_ip or "")
        n.country_code = cc
        if cc in ALLOWED_COUNTRIES:
            n.country_name = ALLOWED_COUNTRIES[cc][1]
            allowed.append(n)
        else:
            n.error = f"blocked country {cc or 'unknown'}"
    return allowed

    @property
    def ip_key(self) -> Tuple[Optional[str], int]:
        return (self.resolved_ip, self.port)




# ---------------------------------------------------------------------------
# Dual-probe stability & real handshake test
# ---------------------------------------------------------------------------

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


async def _single_probe(node: NodeInfo) -> bool:
    ip = node.resolved_ip
    port = node.port
    if not ip:
        return False

    try:
        if node.tls_enabled:
            sni = node.sni or node.host
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip, port, ssl=_SSL_CTX, server_hostname=sni
                ),
                timeout=PROBE_TIMEOUT,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=PROBE_TIMEOUT
        )

        if node.network == "ws":
            probe = (
                f"GET / HTTP/1.1\r\nHost: {node.host}\r\nConnection: close\r\n\r\n"
            ).encode()
            writer.write(probe)
            try:
                await writer.drain()
            except Exception:
                writer.close()
                return False
            try:
                data = await asyncio.wait_for(reader.read(1), timeout=PROBE_TIMEOUT)
            except Exception:
                data = b""
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return bool(data)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def verify_node_stability(node: NodeInfo) -> Optional[Dict[str, Any]]:
    results: List[Optional[bool]] = []
    latencies: List[float] = []

    for i in range(2):
        start = time.monotonic()
        ok = await _single_probe(node)
        elapsed_ms = (time.monotonic() - start) * 1000.0
        results.append(ok)
        latencies.append(elapsed_ms)
        if i == 0:
            await asyncio.sleep(PROBE_GAP)

    if not all(results):
        node.error = "dual probe failed"
        return None

    latency_1, latency_2 = latencies
    avg_ms = round((latency_1 + latency_2) / 2)
    jitter_ms = round(abs(latency_1 - latency_2))
    quality = avg_ms + (jitter_ms * 1.5)

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
    }



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
    main_links: List[str],
) -> Dict[str, Any]:
    _ensure_dirs()

    _write_plain(SERVERS_FILE, main_links)
    _write_b64(SUB_FILE, main_links)

    country_report: Dict[str, Any] = {}
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        nodes = by_country.get(code, [])
        country_links = [n.renamed_link or n.original_link for n in nodes]
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
        proto_links = [n.renamed_link or n.original_link for n in nodes]
        ppath = os.path.join(PROTOCOLS_DIR, f"{proto}.txt")
        pbpath = os.path.join(PROTOCOLS_DIR, f"{proto}_base64.txt")
        _write_plain(ppath, proto_links)
        _write_b64(pbpath, proto_links)

    total_tested = sum(len(v) for v in by_country.values())
    total_passed = sum(len(v) for v in by_country.values())
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
    urls = load_sources()
    if not urls:
        print("[info] No source URLs found in sources.txt.")
        write_all_outputs({}, {}, [])
        return 0

    print(f"[info] Fetching {len(urls)} source URL(s) ...")
    pages = await fetch_all(urls)

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

    # --- Stage 3: DNS + GeoIP filter --------------------------------------
    connector = aiohttp.TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        allowed = await filter_by_geoip(session, parsed)
    print(f"[info] After GeoIP (allowed countries): {len(allowed)} node(s)")

    # --- Stage 4: Dual-probe stability ------------------------------------
    sem = asyncio.Semaphore(MAX_CONCURRENT_PROBES)

    async def _probe(node: NodeInfo) -> None:
        async with sem:
            await verify_node_stability(node)

    await asyncio.gather(*(_probe(n) for n in allowed))

    passed = [n for n in allowed if n.quality_score is not None]
    print(f"[info] After dual-probe stability: {len(passed)} node(s)")

    # --- Stage 5: Group by country & sort by quality ----------------------
    by_country: Dict[str, List[NodeInfo]] = {code: [] for code in ALLOWED_COUNTRIES}
    by_protocol: Dict[str, List[NodeInfo]] = {proto: [] for proto in PROXY_SCHEMES}

    for n in passed:
        cc = n.country_code
        if cc and cc in by_country:
            by_country[cc].append(n)
        by_protocol[n.protocol].append(n)

    for code in by_country:
        by_country[code].sort(key=lambda n: (n.quality_score or float("inf")))

    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda n: (n.quality_score or float("inf")))

    # --- Stage 6: Rename nodes --------------------------------------------
    for code, nodes in by_country.items():
        for idx, n in enumerate(nodes, start=1):
            rename_node(n, code, idx)

    for proto, nodes in by_protocol.items():
        for idx, n in enumerate(nodes, start=1):
            cc = n.country_code or "DE"
            rename_node(n, cc, idx)

    # --- Stage 7: Build main subscription (max 5 per country) -------------
    main_links: List[str] = []
    for code in sorted(ALLOWED_COUNTRIES.keys()):
        nodes = by_country.get(code, [])
        for n in nodes[:MAIN_QUOTA_PER_COUNTRY]:
            main_links.append(n.renamed_link or n.original_link)

    # --- Stage 8: Write outputs -------------------------------------------
    report = write_all_outputs(by_country, by_protocol, main_links)

    # --- Stage 9: GitHub Actions annotations + summary --------------------
    emit_annotations(report["countries"])
    write_step_summary(report["countries"])

    print(f"[info] Total passed: {report['total_passed']}")
    print(f"[info] Main sub count: {report['main_sub_count']}")
    print(f"[info] Alerts (empty countries): {report['alerts']}")
    print(f"[info] Wrote outputs to {OUTPUT_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))



