#!/usr/bin/env python3
"""Modular 2-stage 60-second non-Cloudflare zombie-trap tester."""

from __future__ import annotations

import argparse, base64, collections, json, os, select, shutil, subprocess, sys, threading, time, urllib.request
from typing import Any, Dict, List, Optional, Tuple

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
for p in (REPO_DIR, SCRIPTS_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

import collector, zombie_metrics

SING_BOX_PATH = os.path.expanduser("~/.local/bin/sing-box-direct")
BRIDGE_PORT = 19990
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
G204_URL = "https://www.google.com/generate_204"
STREAM_URL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"
CLEAN_ENV = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}


def run_cmd(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLEAN_ENV, timeout=timeout)


def find_xray_bin() -> str:
    for p in ("/usr/bin/xray", "/home/bellard/Documents/v2rayN-linux-64/xray", "/opt/v2rayN/xray"):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    found = shutil.which("xray")
    if found:
        return found
    raise FileNotFoundError("xray binary not found")


def start_wlan0_bridge() -> subprocess.Popen:
    cfg = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "udp", "tag": "dns-direct", "server": "1.1.1.1", "detour": "direct", "bind_interface": "wlan0"}]},
        "inbounds": [{"type": "mixed", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": BRIDGE_PORT}],
        "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "wlan0"}],
    }
    cfg_file = "/tmp/sb_wlan0_bridge.json"
    with open(cfg_file, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
    time.sleep(0.8)
    try:
        res = run_cmd(["curl", "-s", "-m", "5", "-x", f"socks5h://127.0.0.1:{BRIDGE_PORT}", TRACE_URL], timeout=7)
        if not any(l.strip() == "loc=IR" for l in res.stdout.splitlines()):
            proc.kill()
            sys.exit("ABORT: wlan0 bridge check failed (loc=IR not returned)")
    except Exception as e:
        proc.kill()
        sys.exit(f"ABORT: wlan0 bridge check failed: {e}")
    return proc


def fetch_sub_nodes() -> List[collector.NodeInfo]:
    lines: List[str] = []
    try:
        raw_b64 = subprocess.check_output(
            ["gh", "api", "repos/Ajorvpn/brick-sub-collector/contents/sub.txt?ref=sub", "--jq", ".content"],
            text=True, env=CLEAN_ENV,
        ).strip()
        sub_b64 = base64.b64decode(raw_b64).decode("utf-8", errors="replace").strip()
        lines = [l.strip() for l in base64.b64decode(sub_b64 + "===").decode("utf-8", errors="replace").splitlines() if l.strip()]
    except Exception:
        url = "https://raw.githubusercontent.com/Ajorvpn/brick-sub-collector/sub/sub.txt"
        with urllib.request.urlopen(url, timeout=10) as r:
            dec = base64.b64decode(r.read().decode("utf-8").strip() + "===").decode("utf-8", errors="replace")
            lines = [l.strip() for l in dec.splitlines() if l.strip()]
    nodes = []
    for l in lines:
        n = collector.parse_node_info(l)
        if n:
            nodes.append(n)
    return nodes


def start_xray_batch(batch: List[Tuple[int, collector.NodeInfo]], base_port: int, xray_bin: str) -> Tuple[Optional[subprocess.Popen], str, List[int]]:
    inbounds, outbounds, rules, ports = [], [], [], []
    bridge_ob = {"protocol": "socks", "tag": "wlan0-bridge", "settings": {"servers": [{"address": "127.0.0.1", "port": BRIDGE_PORT}]}}
    for idx, node in batch:
        port = base_port + idx
        ob = collector.build_xray_outbound_for_node(node, f"out-{idx}")
        if not ob:
            continue
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "wlan0-bridge"
        inbounds.append({"tag": f"in-{idx}", "port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}})
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in-{idx}"], "outboundTag": f"out-{idx}"})
        ports.append(port)

    if not outbounds:
        return None, "", []
    cfg = {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds + [bridge_ob], "routing": {"domainStrategy": "AsIs", "rules": rules}}
    cfg_file = f"/tmp/xray_batch_{base_port}.json"
    with open(cfg_file, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    proc = subprocess.Popen([xray_bin, "run", "-c", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
    time.sleep(0.8)
    return proc, cfg_file, ports


def test_stage1_node(port: int) -> bool:
    try:
        t_res = run_cmd(["curl", "-s", "-m", "5", "-x", f"socks5h://127.0.0.1:{port}", TRACE_URL], timeout=6)
        loc = next((l.split("=", 1)[1].strip() for l in t_res.stdout.splitlines() if l.startswith("loc=")), None)
        if not loc or loc == "IR":
            return False
        g_res = run_cmd(["curl", "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"socks5h://127.0.0.1:{port}", G204_URL], timeout=6)
        return g_res.stdout.strip() == "204"
    except Exception:
        return False


def measure_node_stream(port: int, duration: int, rate_kbps: int) -> Tuple[List[float], bool]:
    probe_t, probe_ok, samples = max(1, int(duration * 0.67)), False, []

    def run_probe():
        nonlocal probe_ok
        p = run_cmd(["curl", "-s", "-m", "5", "-o", "/dev/null", "-w", "%{http_code}", "-x", f"socks5h://127.0.0.1:{port}", G204_URL], timeout=6)
        probe_ok = (p.stdout.strip() == "204")

    cmd = ["curl", "-s", "-N", "--limit-rate", f"{rate_kbps}k", "-x", f"socks5h://127.0.0.1:{port}", STREAM_URL]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
    probe_th, start_t = None, time.monotonic()

    for sec in range(duration):
        sec_start, sec_bytes = time.monotonic(), 0
        if not probe_th and (sec_start - start_t) >= probe_t:
            probe_th = threading.Thread(target=run_probe)
            probe_th.start()
        while time.monotonic() - sec_start < 1.0:
            if proc.poll() is not None:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
            try:
                r, _, _ = select.select([proc.stdout], [], [], max(0.01, 1.0 - (time.monotonic() - sec_start)))
                if r:
                    sec_bytes += len(os.read(proc.stdout.fileno(), 65536))
            except Exception:
                time.sleep(0.05)
        samples.append(sec_bytes / 1024.0)

    try:
        proc.terminate()
        proc.wait(timeout=1)
    except Exception:
        proc.kill()
    if probe_th:
        probe_th.join(timeout=6)
    return samples, probe_ok


def main() -> None:
    parser = argparse.ArgumentParser(description="2-Stage 60s Zombie-Trap Tester")
    parser.add_argument("--duration", type=int, default=60)
    parser.add_argument("--stage1-batch", type=int, default=25)
    parser.add_argument("--stage2-batch", type=int, default=12)
    parser.add_argument("--rate-limit-kbps", type=int, default=180)
    parser.add_argument("--max-nodes", type=int, default=0)
    args = parser.parse_args()

    xray_bin = find_xray_bin()
    bridge_proc = start_wlan0_bridge()
    try:
        nodes = fetch_sub_nodes()
        if args.max_nodes > 0:
            nodes = nodes[: args.max_nodes]
        stage1_survivors: List[collector.NodeInfo] = []

        # Stage 1
        for i in range(0, len(nodes), args.stage1_batch):
            chunk = list(enumerate(nodes[i : i + args.stage1_batch]))
            xp, cfg_f, ports = start_xray_batch(chunk, 20000 + i, xray_bin)
            if not xp:
                continue
            try:
                for (sub_idx, node), port in zip(chunk, ports):
                    if test_stage1_node(port):
                        stage1_survivors.append(node)
            finally:
                xp.terminate()
                xp.wait()
                if os.path.exists(cfg_f):
                    os.remove(cfg_f)

        # Stage 2
        stage2_results: List[Dict[str, Any]] = []
        rejections: collections.Counter[str] = collections.Counter()
        failing_samples: List[str] = []

        for i in range(0, len(stage1_survivors), args.stage2_batch):
            chunk = list(enumerate(stage1_survivors[i : i + args.stage2_batch]))
            xp, cfg_f, ports = start_xray_batch(chunk, 30000 + i, xray_bin)
            if not xp:
                continue
            try:
                for (sub_idx, node), port in zip(chunk, ports):
                    samples, probe_ok = measure_node_stream(port, args.duration, args.rate_limit_kbps)
                    res = zombie_metrics.evaluate_stream(samples, probe_ok)
                    if res["passed"]:
                        stage2_results.append({"node": node, "metrics": res})
                    else:
                        rejections[res["reason"]] += 1
                        if len(failing_samples) < 5:
                            failing_samples.append(f"{node.host}:{node.port} (sni={node.sni}) -> {res['reason']}")
            finally:
                xp.terminate()
                xp.wait()
                if os.path.exists(cfg_f):
                    os.remove(cfg_f)

        stage2_results.sort(key=lambda x: x["metrics"]["m_late"], reverse=True)
        plain_links = [s["node"].original_link for s in stage2_results if s["node"].original_link]
        with open("/home/bellard/Documents/working_iran_sub.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(plain_links) + ("\n" if plain_links else ""))
        with open("/home/bellard/Documents/working_iran_sub_b64.txt", "w", encoding="ascii") as f:
            f.write(base64.b64encode(("\n".join(plain_links) + ("\n" if plain_links else "")).encode("utf-8")).decode("ascii"))

        # Compact summary <= 25 lines
        print("================== 60s ZOMBIE-TRAP SUMMARY ==================")
        print(f"Engine: Native Xray ({xray_bin}) via sing-box wlan0 bridge")
        print(f"Funnel: Total {len(nodes)} -> Stage 1: {len(stage1_survivors)} -> Stage 2: {len(stage2_results)}")
        print(f"Zombie Rejections: {dict(rejections)}")
        if failing_samples:
            print("Failing Samples:")
            for fs in failing_samples:
                print(f"  * {fs}")
        print("Top 10 True 60s Survivors:")
        for idx, item in enumerate(stage2_results[:10], start=1):
            n, m = item["node"], item["metrics"]
            print(f"  #{idx:02d}: M_early={m['m_early']} -> M_late={m['m_late']} KB/s | D={m['decay']} | Z_max={m['z_max']}s | {n.protocol} | {n.host}:{n.port}")
        print("=============================================================")
    finally:
        bridge_proc.kill()


if __name__ == "__main__":
    main()
