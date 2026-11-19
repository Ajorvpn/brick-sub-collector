"""Modular Xray and sing-box bridge runner."""
from __future__ import annotations
import glob, json, os, re, shutil, subprocess, sys, time
from typing import Any, Dict, List, Optional, Tuple

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_DIR not in sys.path: sys.path.insert(0, REPO_DIR)
import collector

SING_BOX_PATH = os.path.expanduser("~/.local/bin/sing-box-direct")
BRIDGE_PORT, TRACE_URL = 19990, "https://cloudflare.com/cdn-cgi/trace"
CLEAN_ENV = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
def run_cmd(cmd: List[str], timeout: Optional[float] = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLEAN_ENV, timeout=timeout)
def stop_process(proc: Optional[subprocess.Popen], cfg_file: str = "") -> None:
    if proc:
        try: proc.terminate(); proc.wait(timeout=2)
        except Exception:
            try: proc.kill()
            except Exception: pass
    if cfg_file and os.path.exists(cfg_file):
        try: os.remove(cfg_file)
        except OSError: pass
def find_xray_bin() -> Tuple[str, str]:
    cands = ["/home/bellard/Documents/v2rayN-linux-64/bin/xray/xray", "/opt/v2rayN/bin/xray/xray", "/home/bellard/Documents/v2rayN-linux-64/xray", "/opt/v2rayN/xray", "/usr/bin/xray"]
    w = shutil.which("xray")
    if w: cands.append(w)
    cands.extend(glob.glob("/home/bellard/Documents/v2rayN-linux-64/**/xray", recursive=True))
    seen, best = set(), (-1, -1, -1, "", "")
    for p in cands:
        if not p or not os.path.isfile(p) or not os.access(p, os.X_OK): continue
        rp = os.path.realpath(p)
        if rp in seen: continue
        seen.add(rp)
        try:
            out = subprocess.run([p, "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=CLEAN_ENV, timeout=3).stdout
            m = re.search(r"Xray\s+(\d+)\.(\d+)\.(\d+)", out)
            if m:
                tup = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
                if tup > (best[0], best[1], best[2]): best = (tup[0], tup[1], tup[2], p, f"{m.group(1)}.{m.group(2)}.{m.group(3)}")
        except Exception: continue
    if best[3]: return best[3], best[4]
    raise FileNotFoundError("xray binary not found")
def start_wlan0_bridge() -> Tuple[subprocess.Popen, str]:
    cfg = {
        "log": {"level": "warn"},
        "dns": {"servers": [{"type": "udp", "tag": "dns-direct", "server": "1.1.1.1", "detour": "direct", "bind_interface": "wlan0"}]},
        "inbounds": [{"type": "mixed", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": BRIDGE_PORT}],
        "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "wlan0"}],
    }
    cfg_file = "/tmp/sb_wlan0_bridge.json"
    with open(cfg_file, "w", encoding="utf-8") as f: json.dump(cfg, f)
    chk = run_cmd([SING_BOX_PATH, "check", "-c", cfg_file], timeout=5)
    if chk.returncode != 0:
        stop_process(None, cfg_file)
        sys.exit(f"ABORT: sing-box config check failed: {chk.stderr}")
    proc = subprocess.Popen([SING_BOX_PATH, "run", "-c", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
    time.sleep(0.8)
    for _ in range(3):
        try:
            res = run_cmd(["curl", "-s", "-m", "7", "-x", f"socks5h://127.0.0.1:{BRIDGE_PORT}", TRACE_URL], timeout=9)
            if any(l.strip() == "loc=IR" for l in res.stdout.splitlines()):
                return proc, cfg_file
        except Exception: pass
        time.sleep(0.5)
    stop_process(proc, cfg_file)
    sys.exit("ABORT: wlan0 bridge check failed (loc=IR not returned)")
def build_xray_batch_config(nodes: List[collector.NodeInfo], base_port: int) -> Tuple[Dict[str, Any], List[Tuple[collector.NodeInfo, int]]]:
    inbounds, outbounds, rules, paired = [], [], [], []
    bridge_ob = {"protocol": "socks", "tag": "wlan0-bridge", "settings": {"servers": [{"address": "127.0.0.1", "port": BRIDGE_PORT}]}}
    for idx, node in enumerate(nodes):
        port = base_port + idx
        ob = collector.build_xray_outbound_for_node(node, f"out-{idx}")
        if not ob: continue
        ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = "wlan0-bridge"
        inbounds.append({"tag": f"in-{idx}", "port": port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"auth": "noauth"}})
        outbounds.append(ob)
        rules.append({"type": "field", "inboundTag": [f"in-{idx}"], "outboundTag": f"out-{idx}"})
        paired.append((node, port))
    if not outbounds: return {}, []
    return {"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds + [bridge_ob], "routing": {"domainStrategy": "AsIs", "rules": rules}}, paired
def start_xray_batch(nodes: List[collector.NodeInfo], base_port: int, xray_bin: str) -> Tuple[Optional[subprocess.Popen], str, List[Tuple[collector.NodeInfo, int]]]:
    cfg, paired = build_xray_batch_config(nodes, base_port)
    if not paired: return None, "", []
    cfg_file = f"/tmp/xray_batch_{base_port}.json"
    with open(cfg_file, "w", encoding="utf-8") as f: json.dump(cfg, f)
    if run_cmd([xray_bin, "run", "-test", "-c", cfg_file], timeout=5).returncode != 0:
        good_nodes = []
        for n in nodes:
            scfg, spaired = build_xray_batch_config([n], base_port)
            if not spaired: continue
            tf = f"/tmp/xray_st_{base_port}.json"
            try:
                with open(tf, "w", encoding="utf-8") as f_out: json.dump(scfg, f_out)
                if run_cmd([xray_bin, "run", "-test", "-c", tf], timeout=3).returncode == 0: good_nodes.append(n)
            finally:
                if os.path.exists(tf): os.remove(tf)
        if not good_nodes:
            stop_process(None, cfg_file)
            return None, "", []
        cfg, paired = build_xray_batch_config(good_nodes, base_port)
        with open(cfg_file, "w", encoding="utf-8") as f: json.dump(cfg, f)
    proc = subprocess.Popen([xray_bin, "run", "-c", cfg_file], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=CLEAN_ENV)
    time.sleep(0.6)
    if proc.poll() is not None:
        err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        for l in err.splitlines()[:2]: print(f"[xray error] {l}")
        stop_process(proc, cfg_file)
        return None, "", []
    return proc, cfg_file, paired
