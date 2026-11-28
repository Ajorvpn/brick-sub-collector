#!/usr/bin/env python3
"""OPSEC-hardened inside-Iran Stage-2 verifier and tunnel-isolated publisher.

Pipeline:
  1. Direct ``<interface>`` negative control (``1.1.1.1/cdn-cgi/trace`` -> must be ``IR``).
  2. Shuffled micro-batch probing (concurrency clamped ``1..4``, random jitter,
     anti-penalty-box circuit breaker) using ``sing-box v1.14.4`` bound strictly
     to ``--interface``.
  3. Reuses ``collector._probe_singbox_port`` (``trace`` exit-IP + ``30KB gstatic``
     ``1.webp`` Strict TLS + ``ipify`` consistency).
  4. Anti-zombie hold on balanced finalists (``--zombie-hold-sec``, delayed ``1.sm.webp``).
  5. Canonical ``collector.write_all_outputs`` into ``--output-dir``.
  6. Optional ``--publish`` pushes ``sub`` strictly through the #1 verified survivor proxy.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple, Union

import aiohttp

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import collector  # noqa: E402

PROXY_ENV_VARS: Tuple[str, ...] = (
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
)
ZOMBIE_PROBE_URL = "https://www.gstatic.com/webp/gallery/1.sm.webp"
ZOMBIE_MIN_BYTES = 10_000
ZOMBIE_PROBE_TIMEOUT = 6.0


class NegativeControlError(RuntimeError):
    """Raised when direct interface egress is not inside Iran (``IR``)."""


def clean_subprocess_env(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a copy of ``os.environ`` stripped of proxy environment variables."""
    env = {k: v for k, v in os.environ.items() if k not in PROXY_ENV_VARS}
    if extra:
        env.update(extra)
    return env


def clamp_concurrency(value: int) -> int:
    """Clamp Stage-2 probing concurrency to ``1..4`` to avoid carrier throttling."""
    return max(1, min(4, int(value)))


def find_singbox_v1144_binary(explicit: Optional[str] = None) -> Optional[str]:
    """Locate sing-box binary (explicit -> SINGBOX_BIN -> ~/.local/bin/sing-box-direct if 1.14.4 -> PATH)."""
    for candidate in (explicit, os.environ.get("SINGBOX_BIN")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    direct_path = os.path.expanduser("~/.local/bin/sing-box-direct")
    if os.path.isfile(direct_path) and os.access(direct_path, os.X_OK):
        try:
            res = subprocess.run(
                [direct_path, "version"],
                env=clean_subprocess_env(),
                capture_output=True,
                text=True,
                timeout=3.0,
            )
            if "1.14.4" in (res.stdout or ""):
                return direct_path
        except Exception:
            pass

    which_path = shutil.which("sing-box")
    if which_path and os.path.isfile(which_path) and os.access(which_path, os.X_OK):
        return which_path
    return None


def verify_direct_iran_control(
    interface: str = "wlan0",
    return_rtt: bool = False,
) -> Union[str, Tuple[str, float]]:
    """Verify direct ``<interface>`` egress resolves to ``loc=IR``.

    Aborts immediately (``NegativeControlError``) if ``loc != IR`` so we never
    inadvertently probe proxies nested inside a host VPN tunnel. When
    ``return_rtt=True``, returns ``(loc, elapsed_seconds)``.
    """
    started = time.monotonic()
    try:
        res = subprocess.run(
            [
                "curl",
                "--interface",
                interface,
                "-sS",
                "-m",
                "7",
                collector.SINGBOX_TRACE_URL,
            ],
            env=clean_subprocess_env(),
            capture_output=True,
            text=True,
            timeout=9.0,
        )
    except Exception as exc:
        raise NegativeControlError(
            f"ABORT: direct {interface} negative control failed ({type(exc).__name__}); "
            "refusing to run!"
        ) from exc

    elapsed = max(0.0, time.monotonic() - started)
    if res.returncode != 0:
        raise NegativeControlError(
            f"ABORT: direct {interface} negative control returned rc={res.returncode} "
            "instead of IR — refusing to run through host VPN!"
        )

    loc = ""
    for line in (res.stdout or "").splitlines():
        k, _, v = line.strip().partition("=")
        if k == "loc":
            loc = v.strip().upper()
            break
    if loc != "IR":
        raise NegativeControlError(
            f"ABORT: direct {interface} negative control returned loc={loc or 'UNKNOWN'} "
            "instead of IR — refusing to run through host VPN!"
        )
    return (loc, elapsed) if return_rtt else loc


def fetch_remote_candidates(repo_slug: str, fetch_direct: bool = False) -> str:
    """Fetch ``candidates.txt`` (fallback ``sub.txt``) from ``refs/heads/sub``."""
    urls = (
        f"https://raw.githubusercontent.com/{repo_slug}/sub/candidates.txt",
        f"https://raw.githubusercontent.com/{repo_slug}/sub/sub.txt",
    )
    opener = (
        urllib.request.build_opener(urllib.request.ProxyHandler({}))
        if fetch_direct
        else urllib.request.build_opener()
    )
    last_err: Optional[Exception] = None
    for url in urls:
        try:
            with opener.open(url, timeout=15.0) as resp:
                if getattr(resp, "status", 200) == 200:
                    return resp.read().decode("utf-8", errors="replace")
        except Exception as exc:
            last_err = exc
    raise RuntimeError(
        f"Could not fetch Stage-1 candidates from {repo_slug}: {last_err}"
    )


def _load_candidates_meta(
    input_path: Optional[str],
    repo_slug: str,
    fetch_direct: bool,
) -> List[str]:
    """Load optional tier list (``'primary'`` / ``'backfill'``) from sibling metadata."""
    try:
        if input_path:
            meta_path = os.path.join(
                os.path.dirname(os.path.abspath(input_path)), "candidates_meta.json"
            )
            if os.path.isfile(meta_path):
                with open(meta_path, "r", encoding="utf-8") as mf:
                    data = json.load(mf)
                if isinstance(data, dict) and isinstance(data.get("tiers"), list):
                    return [str(t) for t in data["tiers"]]
        else:
            url = f"https://raw.githubusercontent.com/{repo_slug}/sub/candidates_meta.json"
            opener = (
                urllib.request.build_opener(urllib.request.ProxyHandler({}))
                if fetch_direct
                else urllib.request.build_opener()
            )
            with opener.open(url, timeout=8.0) as resp:
                if getattr(resp, "status", 200) == 200:
                    data = json.loads(resp.read().decode("utf-8", errors="replace"))
                    if isinstance(data, dict) and isinstance(data.get("tiers"), list):
                        return [str(t) for t in data["tiers"]]
    except Exception:
        pass
    return []


def load_candidate_nodes(
    input_path: Optional[str],
    repo_slug: str,
    fetch_direct: bool = False,
) -> List[collector.NodeInfo]:
    """Parse deduplicated candidate links into ``NodeInfo`` objects with tier tags."""
    if input_path:
        with open(input_path, "r", encoding="utf-8") as f:
            raw_text = f.read()
    else:
        raw_text = fetch_remote_candidates(repo_slug, fetch_direct=fetch_direct)

    tiers = _load_candidates_meta(input_path, repo_slug, fetch_direct=fetch_direct)
    links = collector.extract_links(raw_text)
    seen: set = set()
    nodes: List[collector.NodeInfo] = []
    for idx, ln in enumerate(links):
        node = collector.parse_node_info(ln)
        if node is None or node.key in seen:
            continue
        seen.add(node.key)
        # Stage-1 candidates are already verified upstream (keeps SS/VMess eligible).
        node.iran_verified = True
        if idx < len(tiers):
            is_primary = tiers[idx] == "primary"
            node.top_iran_tier = is_primary
            node.aistudio_only = not is_primary
            if is_primary:
                node.openray_rank = idx + 1
        nodes.append(node)
    return nodes


def build_stage2_singbox_config(
    entries: Sequence[Tuple[collector.NodeInfo, int, Dict[str, Any]]],
    bind_interface: str,
) -> Dict[str, Any]:
    """Build Stage-2 sing-box v1.14.4 config bound strictly to *bind_interface*."""
    cfg = collector._build_singbox_batch_config(entries, bind_interface=bind_interface)
    cfg["dns"] = {
        "servers": [
            {
                "tag": "dns-direct",
                "type": "udp",
                "server": "1.1.1.1",
                "detour": "direct",
            }
        ],
        "strategy": "ipv4_only",
    }
    cfg.setdefault("route", {})["default_domain_resolver"] = "dns-direct"
    return cfg


async def _bisect_valid_stage2_entries(
    binary: str,
    entries: List[Tuple[collector.NodeInfo, int, Dict[str, Any]]],
    bind_interface: str,
) -> List[Tuple[collector.NodeInfo, int, Dict[str, Any]]]:
    if not entries:
        return []
    if await collector._singbox_check_config(
        binary, build_stage2_singbox_config(entries, bind_interface=bind_interface)
    ):
        return entries
    if len(entries) == 1:
        return []
    mid = len(entries) // 2
    left = await _bisect_valid_stage2_entries(binary, entries[:mid], bind_interface)
    right = await _bisect_valid_stage2_entries(binary, entries[mid:], bind_interface)
    return left + right


@contextlib.asynccontextmanager
async def _running_singbox_entries(
    binary: str,
    nodes: Sequence[collector.NodeInfo],
    bind_interface: str,
    connect_timeout: str = "4s",
) -> Iterator[List[Tuple[collector.NodeInfo, int, Dict[str, Any]]]]:
    ports = collector._allocate_free_ports(len(nodes))
    raw_entries: List[Tuple[collector.NodeInfo, int, Dict[str, Any]]] = []
    for idx, (node, port) in enumerate(zip(nodes, ports)):
        ob = collector.build_singbox_outbound_for_node(
            node,
            f"ir_out_{idx}",
            bind_interface=bind_interface,
            connect_timeout=connect_timeout,
        )
        if ob is not None:
            raw_entries.append((node, port, ob))
    if not raw_entries:
        yield []
        return

    valid_entries = await _bisect_valid_stage2_entries(
        binary, raw_entries, bind_interface=bind_interface
    )
    if not valid_entries:
        yield []
        return

    cfg = build_stage2_singbox_config(valid_entries, bind_interface=bind_interface)
    fd, cfg_path = tempfile.mkstemp(prefix="brick_ir_sb_", suffix=".json")
    proc: Optional[asyncio.subprocess.Process] = None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        proc = await asyncio.create_subprocess_exec(
            binary,
            "run",
            "-c",
            cfg_path,
            env=clean_subprocess_env(),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        if not await collector._wait_for_tcp_port(valid_entries[0][1]):
            yield []
            return
        yield valid_entries
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except Exception:
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
        try:
            os.remove(cfg_path)
        except OSError:
            pass


def _select_balanced_finalists(
    survivors: Sequence[collector.NodeInfo],
    max_finalists: int,
) -> List[collector.NodeInfo]:
    """Select up to *max_finalists* exit-deduped survivors balanced across countries."""
    if max_finalists <= 0 or not survivors:
        return []
    deduped = collector.dedupe_by_exit_ip(survivors)
    by_country: Dict[str, List[collector.NodeInfo]] = {}
    for n in deduped:
        cc = (getattr(n, "exit_country", None) or n.country_code or "").upper()
        if cc in collector.ALLOWED_COUNTRIES:
            by_country.setdefault(cc, []).append(n)
    for bucket in by_country.values():
        bucket.sort(key=lambda n: int(n.avg_latency_ms or 999999))

    picked: List[collector.NodeInfo] = []
    slot = 0
    while len(picked) < max_finalists:
        progressed = False
        for cc in sorted(by_country.keys()):
            bucket = by_country[cc]
            if slot < len(bucket):
                picked.append(bucket[slot])
                progressed = True
                if len(picked) >= max_finalists:
                    break
        if not progressed:
            break
        slot += 1
    return picked


async def _probe_zombie_port(session: aiohttp.ClientSession, port: int) -> bool:
    """Confirm persistent connection survives delayed ``1.sm.webp`` strict-TLS fetch."""
    proxy = f"http://127.0.0.1:{port}"
    try:
        async with session.get(
            ZOMBIE_PROBE_URL,
            proxy=proxy,
            ssl=collector._STRICT_TLS_CTX,
            timeout=aiohttp.ClientTimeout(total=ZOMBIE_PROBE_TIMEOUT),
            allow_redirects=False,
        ) as resp:
            if resp.status != 200:
                return False
            body = await resp.read()
            return len(body) >= ZOMBIE_MIN_BYTES
    except Exception:
        return False


async def verify_anti_zombie_finalists(
    binary: str,
    finalists: Sequence[collector.NodeInfo],
    interface: str,
    hold_sec: float,
    concurrency: int = 4,
    connect_timeout: str = "4s",
) -> Tuple[List[collector.NodeInfo], int]:
    """Wait *hold_sec* on live listeners, then re-probe ``1.sm.webp`` to drop zombies."""
    if not finalists or hold_sec <= 0:
        return list(finalists), 0

    passed: List[collector.NodeInfo] = []
    async with _running_singbox_entries(
        binary, finalists, interface, connect_timeout=connect_timeout
    ) as valid_entries:
        if not valid_entries:
            return [], len(finalists)
        await asyncio.sleep(hold_sec)
        sem = asyncio.Semaphore(max(1, min(8, concurrency * 2)))
        connector = aiohttp.TCPConnector(limit=16)
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            async def _check_one(node: collector.NodeInfo, port: int) -> Optional[collector.NodeInfo]:
                async with sem:
                    if await _probe_zombie_port(session, port):
                        return node
                    return None

            results = await asyncio.gather(
                *(_check_one(n, p) for n, p, _ in valid_entries)
            )
            passed = [n for n in results if n is not None]

    dropped = len(finalists) - len(passed)
    return passed, dropped


def _tiered_shuffle(
    candidates: Sequence[collector.NodeInfo],
    rng: random.Random,
) -> List[collector.NodeInfo]:
    """Shuffle primary candidates first and secondary backfill second for OPSEC + yield."""
    pool = list(candidates)
    has_tier_tags = any(getattr(n, "top_iran_tier", False) for n in pool) or any(
        getattr(n, "aistudio_only", False) for n in pool
    )
    if has_tier_tags:
        primary = [n for n in pool if not getattr(n, "aistudio_only", False)]
        backfill = [n for n in pool if getattr(n, "aistudio_only", False)]
    else:
        mid = len(pool) // 2 if len(pool) > 1 else len(pool)
        primary = pool[:mid]
        backfill = pool[mid:]
    rng.shuffle(primary)
    rng.shuffle(backfill)
    return primary + backfill


async def probe_candidates_inside_iran(
    candidates: Sequence[collector.NodeInfo],
    binary: str,
    interface: str = "wlan0",
    max_candidates: int = 80,
    concurrency: int = 2,
    jitter_min: float = 1.5,
    jitter_max: float = 3.5,
    circuit_breaker_streak: int = 5,
    circuit_breaker_cooldown: float = 45.0,
    trace_timeout: float = 6.0,
    payload_timeout: float = 9.0,
    connect_timeout: str = "4s",
    seed: Optional[int] = None,
) -> Dict[str, Any]:
    """Tier-shuffled micro-batch probe strictly via *interface* with adaptive breaker."""
    rng = random.Random(seed)
    pool = _tiered_shuffle(candidates, rng)
    if max_candidates > 0:
        pool = pool[:max_candidates]

    conc = clamp_concurrency(concurrency)
    lo_jit = max(0.0, min(jitter_min, jitter_max))
    hi_jit = max(lo_jit, max(jitter_min, jitter_max))
    streak_limit = max(1, int(circuit_breaker_streak))

    ab_survivors: List[collector.NodeInfo] = []
    buckets: Counter = Counter()
    consecutive_timeouts = 0
    circuit_breaker_triggers = 0
    tested_count = 0

    connector = aiohttp.TCPConnector(limit=conc * 2)
    async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
        for start in range(0, len(pool), conc):
            batch = pool[start : start + conc]
            tested_count += len(batch)
            async with _running_singbox_entries(
                binary, batch, interface, connect_timeout=connect_timeout
            ) as valid_entries:
                if not valid_entries:
                    outcomes = [(n, False, "singbox_check_fail") for n in batch]
                else:
                    async def _run_one(
                        n: collector.NodeInfo, p: int
                    ) -> Tuple[collector.NodeInfo, bool, str]:
                        res = await collector._probe_singbox_port(
                            session,
                            p,
                            n,
                            trace_timeout=trace_timeout,
                            payload_timeout=payload_timeout,
                            return_reason=True,
                        )
                        if isinstance(res, tuple):
                            return (n, bool(res[0]), str(res[1]))
                        ok_bool = bool(res)
                        return (n, ok_bool, "ok" if ok_bool else "step_a_timeout")

                    outcomes = list(
                        await asyncio.gather(
                            *(_run_one(n, p) for n, p, _ in valid_entries)
                        )
                    )
                    probed_ids = {id(n) for n, _, _ in valid_entries}
                    for n in batch:
                        if id(n) not in probed_ids:
                            outcomes.append((n, False, "singbox_check_fail"))

            for node, ok, reason in outcomes:
                buckets[reason] += 1
                if ok:
                    consecutive_timeouts = 0
                    ec = (getattr(node, "exit_country", None) or "").upper()
                    if ec in collector.ALLOWED_COUNTRIES:
                        ab_survivors.append(node)
                elif reason == "step_a_timeout":
                    consecutive_timeouts += 1
                    if consecutive_timeouts >= streak_limit:
                        circuit_breaker_triggers += 1
                        ctrl = verify_direct_iran_control(interface, return_rtt=True)
                        if isinstance(ctrl, tuple):
                            loc, direct_rtt = ctrl
                        else:
                            loc, direct_rtt = str(ctrl), 99.0
                        sleep_sec = (
                            min(circuit_breaker_cooldown, 10.0)
                            if direct_rtt < 2.0
                            else circuit_breaker_cooldown
                        )
                        print(
                            f"[breaker] timeout_streak={consecutive_timeouts} on {interface} "
                            f"(direct loc={loc}, direct_rtt={direct_rtt:.2f}s); "
                            f"cooling down {sleep_sec:.1f}s",
                            flush=True,
                        )
                        await asyncio.sleep(sleep_sec)
                        consecutive_timeouts = 0

            if start + conc < len(pool) and hi_jit > 0:
                await asyncio.sleep(rng.uniform(lo_jit, hi_jit))

    return {
        "tested": tested_count,
        "ab_survivors": ab_survivors,
        "circuit_breaker_triggers": circuit_breaker_triggers,
        "failure_buckets": dict(sorted(buckets.items())),
    }


@contextlib.contextmanager
def _collector_output_dir(output_dir: str) -> Iterator[None]:
    """Temporarily point ``collector`` output paths at *output_dir*."""
    saved = {
        "OUTPUT_DIR": collector.OUTPUT_DIR,
        "COUNTRIES_DIR": collector.COUNTRIES_DIR,
        "PROTOCOLS_DIR": collector.PROTOCOLS_DIR,
        "SERVERS_FILE": collector.SERVERS_FILE,
        "SUB_FILE": collector.SUB_FILE,
        "CANDIDATES_FILE": collector.CANDIDATES_FILE,
        "CANDIDATES_META_FILE": collector.CANDIDATES_META_FILE,
        "STATUS_FILE": collector.STATUS_FILE,
    }
    try:
        collector.OUTPUT_DIR = output_dir
        collector.COUNTRIES_DIR = os.path.join(output_dir, "countries")
        collector.PROTOCOLS_DIR = os.path.join(output_dir, "protocols")
        collector.SERVERS_FILE = os.path.join(output_dir, "servers.txt")
        collector.SUB_FILE = os.path.join(output_dir, "sub.txt")
        collector.CANDIDATES_FILE = os.path.join(output_dir, "candidates.txt")
        collector.CANDIDATES_META_FILE = os.path.join(output_dir, "candidates_meta.json")
        collector.STATUS_FILE = os.path.join(output_dir, "status.json")
        yield
    finally:
        for attr, val in saved.items():
            setattr(collector, attr, val)


def write_stage2_outputs(
    survivors: Sequence[collector.NodeInfo],
    output_dir: str,
    total_tested: int,
) -> Dict[str, Any]:
    """Write canonical BrickVPN subscription files into *output_dir*."""
    by_country: Dict[str, List[collector.NodeInfo]] = {
        code: [] for code in collector.ALLOWED_COUNTRIES
    }
    by_protocol: Dict[str, List[collector.NodeInfo]] = {
        proto: [] for proto in collector.PROXY_SCHEMES
    }
    for n in survivors:
        cc = (getattr(n, "exit_country", None) or n.country_code or "").upper()
        if cc in by_country:
            by_country[cc].append(n)
        if n.protocol in by_protocol:
            by_protocol[n.protocol].append(n)

    with _collector_output_dir(output_dir):
        return collector.write_all_outputs(
            by_country,
            by_protocol,
            total_tested=total_tested,
            total_passed=len(survivors),
        )


async def publish_via_survivor_proxy(
    survivors: Sequence[collector.NodeInfo],
    output_dir: str,
    binary: str,
    interface: str,
    repo_slug: str,
) -> None:
    """Force-push *output_dir* to ``refs/heads/sub`` strictly via #1 survivor proxy."""
    if not survivors:
        raise RuntimeError("Refusing --publish: zero verified survivors available.")
    token = (
        os.environ.get("BRICK_SUB_PUSH_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or ""
    ).strip()
    if not token:
        raise RuntimeError(
            "Refusing --publish: BRICK_SUB_PUSH_TOKEN / GITHUB_TOKEN is not set."
        )

    best = min(
        survivors,
        key=lambda n: int(n.avg_latency_ms or 999999),
    )
    async with _running_singbox_entries(binary, [best], interface) as entries:
        if not entries:
            raise RuntimeError("Could not start survivor proxy for --publish.")
        port = entries[0][1]
        proxy_url = f"http://127.0.0.1:{port}"
        connector = aiohttp.TCPConnector(limit=4)
        async with aiohttp.ClientSession(connector=connector, trust_env=False) as session:
            async with session.get(
                collector.SINGBOX_TRACE_URL,
                proxy=proxy_url,
                ssl=collector._STRICT_TLS_CTX,
                timeout=aiohttp.ClientTimeout(total=8.0),
            ) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"Survivor proxy trace check HTTP {resp.status}")
                text = await resp.text(errors="replace")
        proxy_loc = ""
        for ln in text.splitlines():
            k, _, v = ln.strip().partition("=")
            if k == "loc":
                proxy_loc = v.strip().upper()
                break
        if not proxy_loc or proxy_loc == "IR":
            raise RuntimeError(
                f"Refusing --publish: survivor proxy returned invalid loc={proxy_loc or 'EMPTY'}"
            )

        publish_dir = tempfile.mkdtemp(prefix="brick_ir_pub_")
        env = clean_subprocess_env({"GIT_TERMINAL_PROMPT": "0"})
        remote_url = f"https://x-access-token:{token}@github.com/{repo_slug}.git"
        try:
            shutil.copytree(output_dir, publish_dir, dirs_exist_ok=True)
            for cmd in (
                ["git", "-C", publish_dir, "init", "-q", "-b", "sub"],
                ["git", "-C", publish_dir, "config", "user.name", "brick-iran-verifier"],
                ["git", "-C", publish_dir, "config", "user.email", "noreply@local"],
                ["git", "-C", publish_dir, "add", "-A"],
                ["git", "-C", publish_dir, "commit", "-q", "-m", "Update Iran-verified subscriptions"],
                [
                    "git",
                    "-C",
                    publish_dir,
                    "-c",
                    f"http.proxy={proxy_url}",
                    "-c",
                    f"https.proxy={proxy_url}",
                    "push",
                    "--force",
                    remote_url,
                    "HEAD:refs/heads/sub",
                ],
            ):
                res = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30.0)
                if res.returncode != 0:
                    safe_err = (res.stderr or "").replace(token, "[REDACTED]")
                    raise RuntimeError(f"git command failed (rc={res.returncode}): {safe_err}")
        finally:
            shutil.rmtree(publish_dir, ignore_errors=True)


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Inside-Iran Stage-2 wlan0 verifier & publisher")
    p.add_argument("--input", default=None, help="Optional local candidates file")
    p.add_argument("--fetch-direct", action="store_true", help="Strip proxy env when fetching remote candidates")
    p.add_argument("--interface", default="wlan0", help="Egress interface to bind (default: wlan0)")
    p.add_argument("--singbox-bin", default=None, help="Path to sing-box v1.14.4 binary")
    p.add_argument("--output-dir", default="output_iran", help="Target output directory (default: output_iran)")
    p.add_argument("--max-candidates", type=int, default=80, help="Max candidates to probe (0=all)")
    p.add_argument("--concurrency", type=int, default=2, help="Batch size clamped 1..4 (default: 2)")
    p.add_argument("--jitter-min", type=float, default=1.5, help="Min sleep seconds between batches")
    p.add_argument("--jitter-max", type=float, default=3.5, help="Max sleep seconds between batches")
    p.add_argument("--circuit-breaker-streak", type=int, default=5, help="Consecutive timeout failures before cooldown")
    p.add_argument("--circuit-breaker-cooldown", type=float, default=45.0, help="Full cooldown sleep seconds when direct check is slow/degraded")
    p.add_argument("--trace-timeout", type=float, default=6.0, help="Step A trace timeout seconds inside Iran")
    p.add_argument("--payload-timeout", type=float, default=9.0, help="Step B 30KB payload timeout seconds inside Iran")
    p.add_argument("--connect-timeout", default="4s", help="sing-box outbound connect_timeout duration")
    p.add_argument("--zombie-hold-sec", type=float, default=20.0, help="Step D hold duration in seconds (0=off)")
    p.add_argument("--zombie-max-finalists", type=int, default=30, help="Max balanced finalists for Step D")
    p.add_argument("--publish", action="store_true", help="Push sub branch strictly through #1 survivor proxy")
    p.add_argument("--repo-slug", default="Ajorvpn/brick-sub-collector", help="GitHub owner/repo")
    p.add_argument("--seed", type=int, default=None, help="Optional RNG seed for deterministic shuffle")
    return p


async def async_main(args: argparse.Namespace) -> int:
    loc = verify_direct_iran_control(args.interface)
    print(f"NEGATIVE_CONTROL_LOC={loc}", flush=True)

    binary = find_singbox_v1144_binary(args.singbox_bin)
    if not binary:
        print("[error] sing-box v1.14.4 binary not found.", file=sys.stderr)
        return 2

    candidates = load_candidate_nodes(
        args.input, args.repo_slug, fetch_direct=args.fetch_direct
    )
    if not candidates:
        print("[warn] 0 candidate nodes loaded.")
        return 1

    probe_res = await probe_candidates_inside_iran(
        candidates,
        binary=binary,
        interface=args.interface,
        max_candidates=args.max_candidates,
        concurrency=args.concurrency,
        jitter_min=args.jitter_min,
        jitter_max=args.jitter_max,
        circuit_breaker_streak=args.circuit_breaker_streak,
        circuit_breaker_cooldown=args.circuit_breaker_cooldown,
        trace_timeout=args.trace_timeout,
        payload_timeout=args.payload_timeout,
        connect_timeout=args.connect_timeout,
        seed=args.seed,
    )
    ab_survivors: List[collector.NodeInfo] = probe_res["ab_survivors"]
    finalists = _select_balanced_finalists(ab_survivors, args.zombie_max_finalists)
    zombie_survivors, zombie_dropped = await verify_anti_zombie_finalists(
        binary=binary,
        finalists=finalists,
        interface=args.interface,
        hold_sec=args.zombie_hold_sec,
        concurrency=clamp_concurrency(args.concurrency),
        connect_timeout=args.connect_timeout,
    )

    report = write_stage2_outputs(
        zombie_survivors,
        output_dir=args.output_dir,
        total_tested=probe_res["tested"],
    )
    print(
        f"STAGE2_FUNNEL TESTED={probe_res['tested']} "
        f"STEP_AB_PASSED={len(ab_survivors)} "
        f"FINALISTS={len(finalists)} "
        f"ZOMBIE_HOLD_PASSED={len(zombie_survivors)} "
        f"ZOMBIE_DROPPED={zombie_dropped} "
        f"MAIN_SUB_COUNT={report['main_sub_count']} "
        f"CIRCUIT_BREAKER_TRIGGERS={probe_res['circuit_breaker_triggers']}",
        flush=True,
    )
    print(
        f"STAGE2_FAILURE_BUCKETS={json.dumps(probe_res['failure_buckets'])}",
        flush=True,
    )

    if args.publish:
        await publish_via_survivor_proxy(
            zombie_survivors,
            output_dir=args.output_dir,
            binary=binary,
            interface=args.interface,
            repo_slug=args.repo_slug,
        )
        print("PUBLISH_STATUS=OK")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(async_main(args))
    except NegativeControlError as exc:
        print(str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
