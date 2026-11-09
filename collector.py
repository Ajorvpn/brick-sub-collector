#!/usr/bin/env python3
"""
V2Ray / Xray subscription collector and tester.
================================================

Reads subscription URLs from ``sources.txt``, fetches them concurrently with
``asyncio`` + ``aiohttp``, extracts proxy share links, de-duplicates them by
``IP:Port``, tests each node with a lightweight TCP ping, and writes the
surviving nodes to the ``sub/`` directory.

Outputs
-------
sub/proxies.txt
    Plain text, one proxy link per line.
sub/base64.txt
    A single Base64-encoded string of the entire ``proxies.txt`` content.

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
import sys
from typing import List, Optional, Set, Tuple

import aiohttp

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SOURCES_FILE = "sources.txt"
OUTPUT_DIR = "sub"
PROXIES_FILE = os.path.join(OUTPUT_DIR, "proxies.txt")
BASE64_FILE = os.path.join(OUTPUT_DIR, "base64.txt")

FETCH_TIMEOUT = 15.0          # seconds for each HTTP fetch
TCP_PING_TIMEOUT = 3.0        # seconds for each TCP connect test
MAX_CONCURRENT_PINGS = 100    # limit simultaneous socket checks


PROXY_SCHEMES = ("vless", "vmess", "trojan", "ss")

# Matches scheme://... links even when embedded inside HTML or plain text.
# The negated character class stops at whitespace or common HTML delimiters.
PROXY_LINK_RE = re.compile(
    r"(?i)\b(" + "|".join(PROXY_SCHEMES) + r")://[^\s\"'<>()\[\]{}]+"
)

# Heuristic: content that is purely Base64 alphabet (+ whitespace).
PURE_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\s]+$")

# Extracts host:port from scheme://[userinfo@]host:port
AUTHORITY_RE = re.compile(r"://[^@]*@?([^/:]+):(\d+)")


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


async def fetch_url(session: aiohttp.ClientSession, url: str) -> Optional[str]:
    """Fetch a single URL, returning its text or None on any failure."""
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT)
        ) as resp:
            resp.raise_for_status()
            return await resp.text(errors="replace")
    except Exception as exc:  # ClientError, TimeoutError, etc.
        print(f"[fetch] ERROR {url}: {exc}")
        return None


async def fetch_all(urls: List[str]) -> List[Optional[str]]:
    """Fetch all URLs concurrently and return their texts in the same order."""
    connector = aiohttp.TCPConnector(limit_per_host=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        return await asyncio.gather(*(fetch_url(session, u) for u in urls))


def try_base64_decode(text: str) -> Optional[str]:
    """If *text* looks like a Base64 blob, decode it; otherwise return None."""
    stripped = text.strip()
    if not stripped:
        return None
    if not PURE_BASE64_RE.fullmatch(stripped):
        return None
    # Normalise padding so b64decode does not raise on bad length.
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
    """Extract proxy links from raw or Base64-encoded content.

    Both the decoded form (for Base64 subscriptions) and the raw text
    (for links embedded inside HTML/Telegram pages) are scanned.
    """
    found: List[str] = []

    decoded = try_base64_decode(text)
    candidates = [decoded] if decoded is not None else []
    candidates.append(text)  # always scan raw as well

    for candidate in candidates:
        for m in PROXY_LINK_RE.finditer(candidate):
            link = m.group(0).strip().rstrip('.,;:)]}\'"`>')
            if link:
                found.append(link)

    return found


# ---------------------------------------------------------------------------
# Parsing & de-duplication
# ---------------------------------------------------------------------------


def parse_host_port(link: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ``(host, port)`` for a proxy link.

    ``vmess://`` links carry a Base64 JSON config (``add``/``port``).
    Other schemes use ``scheme://[userinfo@]host:port``.
    """
    try:
        if link.lower().startswith("vmess://"):
            b64 = link[len("vmess://"):]
            pad = len(b64) % 4
            if pad:
                b64 += "=" * (4 - pad)
            cfg = json.loads(
                base64.b64decode(b64).decode("utf-8", errors="replace")
            )
            host = cfg.get("add")
            port = cfg.get("port")
            if host and port:
                return str(host), str(port)
    except Exception:
        pass

    m = AUTHORITY_RE.search(link)
    if m:
        return m.group(1), m.group(2)
    return None, None


def deduplicate(links: List[str]) -> List[str]:
    """De-duplicate by IP:Port; fall back to the full link when unparseable."""
    seen: Set[Tuple[Optional[str], Optional[str]]] = set()
    unique: List[str] = []
    for link in links:
        key = parse_host_port(link)
        if key in seen:
            continue
        seen.add(key)
        unique.append(link)
    return unique


# ---------------------------------------------------------------------------
# TCP ping testing
# ---------------------------------------------------------------------------


async def tcp_ping(host: str, port: int, timeout: float = TCP_PING_TIMEOUT) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def test_nodes(links: List[str]) -> List[str]:
    """Test each link; return those whose host:port accepts a TCP connection.

    Links whose address cannot be parsed to a valid host:port are dropped
    immediately and never included in the final output.
    """
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PINGS)

    async def _test(link: str) -> Optional[str]:
        host, port = parse_host_port(link)
        if host is None or port is None:
            return None
        async with semaphore:
            ok = await tcp_ping(host, int(port))
        return link if ok else None

    results = await asyncio.gather(*(_test(l) for l in links))
    return [r for r in results if r is not None]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def write_outputs(active_links: List[str]) -> str:
    """Write proxies.txt and base64.txt; return the plain-text content."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    plain_text = "\n".join(active_links)
    if plain_text:
        plain_text += "\n"

    with open(PROXIES_FILE, "w", encoding="utf-8") as f:
        f.write(plain_text)

    encoded = base64.b64encode(plain_text.encode("utf-8")).decode("ascii")
    with open(BASE64_FILE, "w", encoding="ascii") as f:
        f.write(encoded)

    return plain_text


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def load_sources() -> List[str]:
    """Read non-empty, stripped lines from SOURCES_FILE."""
    if not os.path.exists(SOURCES_FILE):
        print(f"[error] {SOURCES_FILE} not found.", file=sys.stderr)
        return []
    with open(SOURCES_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


async def main() -> int:
    urls = load_sources()
    if not urls:
        print("[info] No source URLs found in sources.txt.")
        write_outputs([])
        return 0

    print(f"[info] Fetching {len(urls)} source URL(s) ...")
    pages = await fetch_all(urls)

    all_links: List[str] = []
    for url, text in zip(urls, pages):
        if not text:
            continue
        links = extract_links(text)
        print(f"[info] {url}: extracted {len(links)} link(s)")
        all_links.extend(links)

    print(f"[info] Total extracted: {len(all_links)} link(s)")

    unique_links = deduplicate(all_links)
    print(f"[info] After de-duplication: {len(unique_links)} link(s)")

    print(f"[info] TCP-ping testing (timeout {TCP_PING_TIMEOUT}s) ...")
    active_links = await test_nodes(unique_links)
    print(f"[info] Active nodes: {len(active_links)} / {len(unique_links)}")

    write_outputs(active_links)
    print(f"[info] Wrote {PROXIES_FILE} and {BASE64_FILE}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
