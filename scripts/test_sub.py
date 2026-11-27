#!/usr/bin/env python3
"""Modular 2-stage 60s zombie-trap tester."""
from __future__ import annotations
import argparse, base64, collections, concurrent.futures, ipaddress, os, subprocess, sys, time, urllib.request
from typing import Any, Dict, List

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
for p in (REPO_DIR, SCRIPTS_DIR):
    if p not in sys.path: sys.path.insert(0, p)
import collector, stream_probe, xray_runner, zombie_metrics

PROXY_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://")

def _parse_sub_lines(raw_text: str) -> List[collector.NodeInfo]:
    text = raw_text.strip()
    if not text:
        return []
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not any(l.lower().startswith(PROXY_SCHEMES) for l in lines):
        compact = "".join(lines)
        try:
            dec = base64.b64decode(compact + "===").decode("utf-8", errors="replace")
            lines = [l.strip() for l in dec.splitlines() if l.strip()]
        except Exception:
            pass
    return [n for l in lines if (n := collector.parse_node_info(l)) is not None]

def load_local_nodes(path: str) -> List[collector.NodeInfo]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return _parse_sub_lines(f.read())

def fetch_sub_nodes() -> List[collector.NodeInfo]:
    lines: List[str] = []
    try:
        raw_b64 = subprocess.check_output(["gh", "api", "repos/Ajorvpn/brick-sub-collector/contents/sub.txt?ref=sub", "--jq", ".content"], text=True, env=xray_runner.CLEAN_ENV).strip()
        sub_b64 = base64.b64decode(raw_b64).decode("utf-8", errors="replace").strip()
        lines = [l.strip() for l in base64.b64decode(sub_b64 + "===").decode("utf-8", errors="replace").splitlines() if l.strip()]
    except Exception:
        url = "https://raw.githubusercontent.com/Ajorvpn/brick-sub-collector/sub/sub.txt"
        with urllib.request.urlopen(url, timeout=10) as r:
            dec = base64.b64decode(r.read().decode("utf-8").strip() + "===").decode("utf-8", errors="replace")
            lines = [l.strip() for l in dec.splitlines() if l.strip()]
    return [n for l in lines if (n := collector.parse_node_info(l)) is not None]

def _is_ip_literal(value: str) -> bool:
    host = value.strip().strip("[]")
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def prioritize_stage2_candidates(nodes: List[collector.NodeInfo]) -> List[collector.NodeInfo]:
    def _rank(n: collector.NodeInfo) -> int:
        sni = (getattr(n, "sni", None) or "").strip().lower()
        if not sni or sni == "none" or _is_ip_literal(sni):
            return 2
        if sni == "fuck.rkn":
            return 1
        return 0
    return sorted(nodes, key=_rank)

def main() -> None:
    parser = argparse.ArgumentParser(description="2-Stage Gentle 65s Zombie-Trap Tester")
    parser.add_argument("--duration", type=int, default=65)
    parser.add_argument("--stage1-batch", type=int, default=6)
    parser.add_argument("--stage2-batch", type=int, default=2)
    parser.add_argument("--rate-limit-kbps", type=int, default=72)
    parser.add_argument("--batch-delay", type=float, default=1.5)
    parser.add_argument("--max-nodes", type=int, default=0)
    parser.add_argument("--max-stage2", type=int, default=15)
    parser.add_argument("--input", type=str, default="")
    args = parser.parse_args()

    xray_bin, xray_ver = xray_runner.find_xray_bin()
    bridge_proc, bridge_cfg = xray_runner.start_wlan0_bridge()
    try:
        nodes = load_local_nodes(args.input) if args.input else fetch_sub_nodes()
        if args.max_nodes > 0: nodes = nodes[: args.max_nodes]
        stage1_survivors: List[collector.NodeInfo] = []

        for i in range(0, len(nodes), args.stage1_batch):
            chunk = nodes[i : i + args.stage1_batch]
            xp, cfg_f, paired = xray_runner.start_xray_batch(chunk, 20000 + i, xray_bin)
            if not xp: continue
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(paired))) as ex:
                    fut_to_node = {ex.submit(stream_probe.test_stage1_node, port): node for node, port in paired}
                    for fut in concurrent.futures.as_completed(fut_to_node):
                        if fut.result(): stage1_survivors.append(fut_to_node[fut])
            finally: xray_runner.stop_process(xp, cfg_f)
            if args.batch_delay > 0 and (i + args.stage1_batch) < len(nodes):
                time.sleep(args.batch_delay)

        stage2_results: List[Dict[str, Any]] = []
        rejections: collections.Counter[str] = collections.Counter()
        failing_samples: List[str] = []

        ordered_s1 = prioritize_stage2_candidates(stage1_survivors)
        stage2_candidates = ordered_s1[: args.max_stage2] if args.max_stage2 > 0 else ordered_s1
        for i in range(0, len(stage2_candidates), args.stage2_batch):
            chunk = stage2_candidates[i : i + args.stage2_batch]
            xp, cfg_f, paired = xray_runner.start_xray_batch(chunk, 30000 + i, xray_bin)
            if not xp: continue
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(paired))) as ex:
                    fut_to_node = {ex.submit(stream_probe.measure_node_stream, port, args.duration, args.rate_limit_kbps): node for node, port in paired}
                    for fut in concurrent.futures.as_completed(fut_to_node):
                        node = fut_to_node[fut]
                        samples, probe_ok = fut.result()
                        res = zombie_metrics.evaluate_stream(samples, probe_ok)
                        if res["passed"]: stage2_results.append({"node": node, "metrics": res})
                        else:
                            rejections[res["reason"]] += 1
                            if len(failing_samples) < 5: failing_samples.append(f"{node.host}:{node.port} (sni={node.sni}) -> {res['reason']}")
            finally: xray_runner.stop_process(xp, cfg_f)

        stage2_results.sort(key=lambda x: x["metrics"]["m_late"], reverse=True)
        plain = [s["node"].original_link for s in stage2_results if s["node"].original_link]
        with open("/home/bellard/Documents/working_iran_sub.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(plain) + ("\n" if plain else ""))
        with open("/home/bellard/Documents/working_iran_sub_b64.txt", "w", encoding="ascii") as f:
            f.write(base64.b64encode(("\n".join(plain) + ("\n" if plain else "")).encode("utf-8")).decode("ascii"))

        proto_tot = collections.Counter(n.protocol.upper() for n in nodes)
        proto_pass = collections.Counter(s["node"].protocol.upper() for s in stage2_results)
        protos = [p for p in ("VLESS", "VMESS", "TROJAN", "SHADOWSOCKS") if proto_tot[p] > 0]
        proto_str = ", ".join(f"{p}={proto_pass[p]}/{proto_tot[p]}" for p in protos)

        print("================== 60s ZOMBIE-TRAP SUMMARY ==================")
        print(f"Engine: Native Xray {xray_ver} ({xray_bin}) via sing-box wlan0 bridge")
        print(f"Funnel: Total {len(nodes)} -> Stage 1: {len(stage1_survivors)} -> Stage 2: {len(stage2_results)}")
        print(f"Stage 2 By Protocol: {proto_str}")
        print(f"Zombie Rejections: {dict(rejections)}")
        if failing_samples:
            print("Failing Samples:")
            for fs in failing_samples: print(f"  * {fs}")
        print("Top 10 True 60s Survivors:")
        for idx, item in enumerate(stage2_results[:10], start=1):
            n, m = item["node"], item["metrics"]
            print(f"  #{idx:02d}: M_early={m['m_early']} -> M_late={m['m_late']} KB/s | D={m['decay']} | Z_max={m['z_max']}s | {n.protocol} | {n.host}:{n.port}")
        print("=============================================================")
    finally: xray_runner.stop_process(bridge_proc, bridge_cfg)

if __name__ == "__main__": main()
