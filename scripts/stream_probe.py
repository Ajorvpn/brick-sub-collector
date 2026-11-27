"""Sustained stream measurement and stage 1 probing."""
from __future__ import annotations
import os, select, subprocess, sys, threading, time
from typing import List, Optional, Tuple

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPTS_DIR not in sys.path: sys.path.insert(0, SCRIPTS_DIR)
import xray_runner

G204_URL = "https://www.google.com/generate_204"
STREAM_URLS = [
    "https://deb.debian.org/debian/ls-lR.gz",
    "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb",
    "https://speed.cloudflare.com/__down?bytes=5000000",
]
MAX_ERROR_RESTARTS = 3

def test_stage1_node(port: int) -> bool:
    try:
        t = xray_runner.run_cmd(["curl", "-s", "-m", "8", "-x", f"socks5h://127.0.0.1:{port}", xray_runner.TRACE_URL], timeout=9)
        lines = [l.strip() for l in t.stdout.splitlines()]
        loc = next((l.split("=", 1)[1].strip() for l in lines if l.startswith("loc=")), None)
        has_ip = any(l.startswith("ip=") for l in lines)
        return bool(loc and loc != "IR" and has_ip)
    except Exception: return False

def _close_proc(p: Optional[subprocess.Popen]) -> None:
    if not p: return
    try:
        if p.stdout: p.stdout.close()
    except Exception: pass
    try:
        p.terminate()
        p.wait(timeout=1)
    except Exception:
        try:
            p.kill()
            p.wait(timeout=1)
        except Exception: pass
def measure_node_stream(port: int, duration: int, rate_kbps: int) -> Tuple[List[float], bool]:
    probe_t, probe_ok, samples = max(1, int(duration * 0.67)), False, []
    def run_probe():
        nonlocal probe_ok
        try:
            p = xray_runner.run_cmd(["curl", "-s", "-m", "8", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"socks5h://127.0.0.1:{port}", G204_URL], timeout=9)
            probe_ok = (p.stdout.strip() == "204")
        except Exception: probe_ok = False

    def _spawn(url: str) -> subprocess.Popen:
        return subprocess.Popen(["curl", "-s", "-L", "-N", "--connect-timeout", "6", "--speed-time", "6", "--speed-limit", "512", "--limit-rate", f"{rate_kbps}k", "-x", f"socks5h://127.0.0.1:{port}", url], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=xray_runner.CLEAN_ENV)

    url_idx, err_restarts, proc_bytes, stream_dead = 0, 0, 0, False
    probe_th, start_t = None, time.monotonic()
    proc: Optional[subprocess.Popen] = _spawn(STREAM_URLS[url_idx])
    try:
        for _ in range(duration):
            sec_start, sec_bytes = time.monotonic(), 0
            if not probe_th and (sec_start - start_t) >= probe_t:
                probe_th = threading.Thread(target=run_probe); probe_th.start()
            if stream_dead:
                rem = 1.0 - (time.monotonic() - sec_start)
                if rem > 0: time.sleep(rem)
                samples.append(0.0); continue
            while time.monotonic() - sec_start < 1.0:
                if proc is None: break
                to = max(0.01, 1.0 - (time.monotonic() - sec_start))
                try: r, _, _ = select.select([proc.stdout], [], [], to)
                except Exception: break
                if r:
                    try: chunk = os.read(proc.stdout.fileno(), 65536)
                    except Exception: chunk = b""
                    if chunk:
                        sec_bytes += len(chunk); proc_bytes += len(chunk)
                    else:
                        rc = proc.poll()
                        if rc is None:
                            try: rc = proc.wait(timeout=0.5)
                            except Exception: pass
                        _close_proc(proc); proc = None
                        if rc == 0 and proc_bytes >= 65536:
                            proc_bytes = 0; proc = _spawn(STREAM_URLS[url_idx])
                        else:
                            err_restarts += 1
                            if err_restarts <= MAX_ERROR_RESTARTS:
                                url_idx = (url_idx + 1) % len(STREAM_URLS); time.sleep(0.4)
                                proc_bytes = 0; proc = _spawn(STREAM_URLS[url_idx])
                            else:
                                stream_dead = True; break
            samples.append(sec_bytes / 1024.0)
    finally:
        _close_proc(proc)
        if probe_th: probe_th.join(timeout=6)
    return samples, probe_ok
