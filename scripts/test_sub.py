#!/usr/bin/env python3
import os
import sys
import json
import base64
import urllib.parse
import urllib.request
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

SING_BOX = os.path.expanduser("~/.local/bin/sing-box-direct")
SUB_URL = "https://raw.githubusercontent.com/Ajorvpn/brick-sub-collector/sub/sub.txt"
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"
PROBE_URL = "http://cp.cloudflare.com/generate_204"
TIMEOUT_SECS = 5
BATCH_SIZE = 8

CLEAN_ENV = os.environ.copy()
for k in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
    CLEAN_ENV.pop(k, None)


def run_cmd(cmd, env=None, timeout=None):
    return subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env or CLEAN_ENV,
        timeout=timeout,
    )


def sanity_check_iran():
    """Verify that direct outbound on wlan0 bypasses TUN and is on IR network."""
    cfg = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "1.1.1.1",
                    "detour": "direct",
                    "bind_interface": "wlan0",
                }
            ]
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "sanity-in",
                "listen": "127.0.0.1",
                "listen_port": 19998,
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct", "bind_interface": "wlan0"}],
    }
    cfg_file = "/tmp/sb_sanity.json"
    with open(cfg_file, "w") as f:
        json.dump(cfg, f)

    check = run_cmd([SING_BOX, "check", "-c", cfg_file])
    if check.returncode != 0:
        print("ABORT: not on direct IR network (sing-box sanity check failed)")
        sys.exit(1)

    proc = subprocess.Popen(
        [SING_BOX, "run", "-c", cfg_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=CLEAN_ENV,
    )
    time.sleep(0.8)
    try:
        curl_res = run_cmd(
            [
                "curl",
                "-s",
                "-m",
                str(TIMEOUT_SECS),
                "-x",
                "socks5h://127.0.0.1:19998",
                TRACE_URL,
            ],
            timeout=TIMEOUT_SECS + 2,
        )
        output = curl_res.stdout
        is_ir = any(line.strip() == "loc=IR" for line in output.splitlines())
        if not is_ir:
            print("ABORT: not on direct IR network")
            sys.exit(1)
    except Exception:
        print("ABORT: not on direct IR network")
        sys.exit(1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()


def parse_link_to_outbound(link, tag):
    scheme = link.split("://", 1)[0].lower()
    clean = link
    if scheme == "ss":
        rest = clean[5:]
        if "#" in rest:
            rest, _ = rest.split("#", 1)
        if "@" in rest:
            user_b64, server_part = rest.split("@", 1)
            pad = len(user_b64) % 4
            if pad:
                user_b64 += "=" * (4 - pad)
            user_dec = base64.b64decode(user_b64).decode("utf-8", errors="ignore")
            method, password = user_dec.split(":", 1)
            host, port = server_part.rsplit(":", 1)
        else:
            pad = len(rest) % 4
            if pad:
                rest += "=" * (4 - pad)
            dec = base64.b64decode(rest).decode("utf-8", errors="ignore")
            user_part, server_part = dec.split("@", 1)
            method, password = user_part.split(":", 1)
            host, port = server_part.rsplit(":", 1)
        return {
            "type": "shadowsocks",
            "tag": tag,
            "server": host,
            "server_port": int(port),
            "method": method,
            "password": password,
            "bind_interface": "wlan0",
        }
    elif scheme == "vmess":
        rest = clean[8:]
        b64 = rest.split("#", 1)[0]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
        host = cfg.get("add", "")
        port = int(cfg.get("port", 0))
        uuid = cfg.get("id", "")
        alter_id = int(cfg.get("aid", 0) or 0)
        net = cfg.get("net", "").lower()
        tls_enabled = str(cfg.get("tls", "")).lower() == "tls"
        sni = cfg.get("sni") or cfg.get("host") or host
        path = cfg.get("path", "")
        ob = {
            "type": "vmess",
            "tag": tag,
            "server": host,
            "server_port": port,
            "uuid": uuid,
            "security": cfg.get("scy", "auto") or "auto",
            "alter_id": alter_id,
            "bind_interface": "wlan0",
        }
        if tls_enabled:
            ob["tls"] = {"enabled": True, "server_name": sni, "insecure": True}
            fp = cfg.get("fp")
            if fp:
                ob["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
        if net == "ws":
            ws_headers = {}
            if cfg.get("host"):
                ws_headers["Host"] = cfg["host"]
            ob["transport"] = {
                "type": "ws",
                "path": path or "/",
                "headers": ws_headers,
            }
        elif net == "grpc":
            ob["transport"] = {
                "type": "grpc",
                "service_name": cfg.get("path", "") or cfg.get("serviceName", ""),
            }
        elif net == "httpupgrade":
            ob["transport"] = {
                "type": "httpupgrade",
                "path": path or "/",
                "host": cfg.get("host", ""),
            }
        return ob
    elif scheme in ("vless", "trojan"):
        u = urllib.parse.urlsplit(clean)
        params = dict(urllib.parse.parse_qsl(u.query))
        host = u.hostname
        port = u.port
        user = u.username or u.path.lstrip("/")
        sec = params.get("security", "").lower()
        net = params.get("type", "").lower()
        sni = params.get("sni") or params.get("host") or host
        fp = params.get("fp", "chrome")
        flow = params.get("flow", "")
        ob = {
            "type": scheme,
            "tag": tag,
            "server": host,
            "server_port": port,
            "bind_interface": "wlan0",
        }
        if scheme == "vless":
            ob["uuid"] = user
            if flow:
                ob["flow"] = flow
        else:
            ob["password"] = user

        if sec in ("tls", "reality") or scheme == "trojan":
            tls_cfg = {"enabled": True, "server_name": sni, "insecure": True}
            if fp:
                tls_cfg["utls"] = {"enabled": True, "fingerprint": fp}
            alpn = [a.strip() for a in params.get("alpn", "").split(",") if a.strip()]
            if alpn:
                tls_cfg["alpn"] = alpn
            if sec == "reality":
                tls_cfg["reality"] = {
                    "enabled": True,
                    "public_key": params.get("pbk", ""),
                    "short_id": params.get("sid", ""),
                }
            ob["tls"] = tls_cfg

        if net == "ws":
            headers = {}
            if params.get("host"):
                headers["Host"] = params["host"]
            ob["transport"] = {
                "type": "ws",
                "path": params.get("path", "/"),
                "headers": headers,
            }
        elif net == "grpc":
            ob["transport"] = {
                "type": "grpc",
                "service_name": params.get("serviceName", ""),
            }
        elif net == "httpupgrade":
            ob["transport"] = {
                "type": "httpupgrade",
                "path": params.get("path", "/"),
                "host": params.get("host", ""),
            }
        return ob
    return None


def probe_node_port(port):
    """Probe Cloudflare generate_204 through local socks5 port."""
    try:
        res = run_cmd(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}:%{time_total}",
                "-m",
                str(TIMEOUT_SECS),
                "-x",
                f"socks5h://127.0.0.1:{port}",
                PROBE_URL,
            ],
            timeout=TIMEOUT_SECS + 2,
        )
        if res.returncode == 0:
            parts = res.stdout.strip().split(":")
            if len(parts) == 2 and parts[0] in ("204", "200"):
                return True, int(float(parts[1]) * 1000), "OK"
            return False, 0, f"HTTP {parts[0]}" if parts else "HTTP Error"
        elif res.returncode == 28:
            return False, 0, "Timeout"
        elif res.returncode in (7, 52, 56):
            return False, 0, "Connection Error"
        elif res.returncode == 97:
            return False, 0, "Proxy Handshake Error"
        else:
            return False, 0, f"Curl Error {res.returncode}"
    except subprocess.TimeoutExpired:
        return False, 0, "Timeout"
    except Exception as e:
        return False, 0, type(e).__name__


def test_batch(batch_items, start_port):
    """Test a batch of nodes concurrently via a single sing-box process."""
    inbounds = []
    outbounds = []
    rules = []
    node_map = {}

    for idx, (node_name, ob) in enumerate(batch_items):
        port = start_port + idx
        in_tag = f"in-{idx}"
        ob_tag = ob["tag"]
        inbounds.append(
            {
                "type": "mixed",
                "tag": in_tag,
                "listen": "127.0.0.1",
                "listen_port": port,
            }
        )
        outbounds.append(ob)
        rules.append({"inbound": [in_tag], "outbound": ob_tag})
        node_map[port] = node_name

    outbounds.append({"type": "direct", "tag": "direct", "bind_interface": "wlan0"})
    cfg = {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "1.1.1.1",
                    "detour": "direct",
                    "bind_interface": "wlan0",
                }
            ]
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules},
    }

    cfg_file = f"/tmp/sb_batch_{start_port}.json"
    with open(cfg_file, "w") as f:
        json.dump(cfg, f)

    # Validate configuration
    chk = run_cmd([SING_BOX, "check", "-c", cfg_file])
    if chk.returncode != 0:
        # Fallback: mark all in batch as Config Error
        return [
            (node_name, False, 0, "Config Check Failed")
            for node_name, _ in batch_items
        ]

    proc = subprocess.Popen(
        [SING_BOX, "run", "-c", cfg_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=CLEAN_ENV,
    )
    time.sleep(0.8)

    results = []
    try:
        with ThreadPoolExecutor(max_workers=len(batch_items)) as executor:
            future_to_info = {
                executor.submit(probe_node_port, start_port + idx): batch_items[idx][0]
                for idx in range(len(batch_items))
            }
            for fut in future_to_info:
                name = future_to_info[fut]
                ok, lat, err = fut.result()
                results.append((name, ok, lat, err))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
        try:
            os.remove(cfg_file)
        except OSError:
            pass

    return results


def main():
    # Step 1: sanity check
    sanity_check_iran()

    # Step 2: fetch sub
    try:
        req = urllib.request.Request(
            SUB_URL,
            headers={"User-Agent": "Mozilla/5.0 (compatible; BrickSubTester/1.0)"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw_data = resp.read()
    except Exception as e:
        print(f"Error fetching subscription: {e}")
        sys.exit(1)

    try:
        decoded = base64.b64decode(raw_data).decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"Error decoding base64 subscription: {e}")
        sys.exit(1)

    raw_lines = [l.strip() for l in decoded.splitlines() if l.strip()]

    # Step 3: parse nodes
    parsed_nodes = []
    error_counts = {}
    for idx, line in enumerate(raw_lines):
        name = f"Node #{idx + 1}"
        if "#" in line:
            name = urllib.parse.unquote(line.split("#", 1)[1].strip())
        elif line.startswith("vmess://"):
            try:
                b64 = line[8:].split("#", 1)[0]
                pad = len(b64) % 4
                if pad:
                    b64 += "=" * (4 - pad)
                cfg = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
                if "ps" in cfg and cfg["ps"]:
                    name = str(cfg["ps"]).strip()
            except Exception:
                pass
        try:
            ob = parse_link_to_outbound(line, f"node-{idx}")
            if ob:
                parsed_nodes.append((name, ob))
            else:
                error_counts["Parse Unsupported"] = (
                    error_counts.get("Parse Unsupported", 0) + 1
                )
        except Exception:
            error_counts["Parse Exception"] = (
                error_counts.get("Parse Exception", 0) + 1
            )

    # Step 4: test in small batches
    working_nodes = []
    base_port = 24000
    for i in range(0, len(parsed_nodes), BATCH_SIZE):
        batch = parsed_nodes[i : i + BATCH_SIZE]
        results = test_batch(batch, base_port + (i % 100))
        for name, ok, lat, err in results:
            if ok:
                working_nodes.append((name, lat))
            else:
                error_counts[err] = error_counts.get(err, 0) + 1

    # Step 5: print concise <=15-line summary
    total = len(raw_lines)
    w_count = len(working_nodes)
    w_pct = (w_count / total * 100) if total > 0 else 0.0
    avg_lat = (
        int(sum(lat for _, lat in working_nodes) / w_count) if w_count > 0 else 0
    )

    working_nodes.sort(key=lambda x: x[1])
    top_working = working_nodes[:5]

    top_errors = sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    err_str = (
        ", ".join(f"{cat}: {cnt}" for cat, cnt in top_errors)
        if top_errors
        else "None"
    )

    print("=== Subscription Test Summary (Direct IR wlan0) ===")
    print(f"Total nodes: {total} | Working: {w_count} ({w_pct:.1f}%)")
    print(f"Average latency: {avg_lat} ms")
    print(f"Top error categories: {err_str}")
    print("Top working nodes:")
    if top_working:
        for i, (name, lat) in enumerate(top_working, 1):
            print(f"  {i}. {name} ({lat} ms)")
    else:
        print("  (none)")
    print("====================================================")


if __name__ == "__main__":
    main()
