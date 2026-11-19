"""Unit tests for scripts/xray_runner.py and scripts/stream_probe.py."""
from __future__ import annotations
import base64, json, os, re, subprocess, sys, tempfile, unittest
from unittest.mock import MagicMock, patch

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_DIR, "scripts")
for p in (REPO_DIR, SCRIPTS_DIR):
    if p not in sys.path: sys.path.insert(0, p)

import collector, stream_probe, xray_runner

class TestTestSub(unittest.TestCase):
    def test_build_xray_batch_config_keeps_node_port_alignment_when_node_skipped(self):
        n1 = collector.parse_node_info("trojan://p1@1.1.1.1:443?security=tls#n1")
        n2 = collector.parse_node_info("trojan://p2@2.2.2.2:443?security=tls#n2")
        n3 = collector.parse_node_info("trojan://p3@3.3.3.3:443?security=tls#n3")
        def mock_builder(node, tag):
            if node == n2: return None
            return {"protocol": "trojan", "tag": tag, "settings": {}}
        with patch.object(collector, "build_xray_outbound_for_node", side_effect=mock_builder):
            cfg, paired = xray_runner.build_xray_batch_config([n1, n2, n3], 20000)
        self.assertEqual(len(paired), 2)
        self.assertEqual(paired[0], (n1, 20000))
        self.assertEqual(paired[1], (n3, 20002))
        for ob in cfg["outbounds"]:
            if ob.get("tag") != "wlan0-bridge":
                self.assertEqual(ob.get("streamSettings", {}).get("sockopt", {}).get("dialerProxy"), "wlan0-bridge")

    def test_measure_node_stream_no_fork_bomb_on_fast_failing_curl(self):
        call_count = 0
        def fake_popen(*args, **kwargs):
            nonlocal call_count; call_count += 1
            r, w = os.pipe(); os.close(w)
            p = MagicMock(); p.stdout = os.fdopen(r, "rb"); p.poll.return_value = 7; p.wait.return_value = 7
            return p
        with patch.object(stream_probe.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(stream_probe.time, "sleep", return_value=None), \
             patch.object(stream_probe.xray_runner, "run_cmd", return_value=subprocess.CompletedProcess([], 0, "204", "")):
            samples, probe_ok = stream_probe.measure_node_stream(port=29999, duration=2, rate_kbps=180)
        self.assertLessEqual(call_count, 1 + stream_probe.MAX_ERROR_RESTARTS)
        self.assertEqual(len(samples), 2)

    def test_measure_node_stream_handles_probe_timeout_without_crash(self):
        def fake_popen(*args, **kwargs):
            r, w = os.pipe(); os.close(w)
            p = MagicMock(); p.stdout = os.fdopen(r, "rb"); p.poll.return_value = 7; p.wait.return_value = 7
            return p
        with patch.object(stream_probe.subprocess, "Popen", side_effect=fake_popen), \
             patch.object(stream_probe.time, "sleep", return_value=None), \
             patch.object(stream_probe.xray_runner, "run_cmd", side_effect=subprocess.TimeoutExpired(cmd="curl", timeout=6)):
            samples, probe_ok = stream_probe.measure_node_stream(port=29999, duration=1, rate_kbps=180)
        self.assertFalse(probe_ok)

    def test_find_xray_bin_returns_executable_and_version(self):
        p, ver = xray_runner.find_xray_bin()
        self.assertTrue(os.path.isfile(p) and os.access(p, os.X_OK))
        self.assertTrue(re.match(r"^\d+\.\d+\.\d+$", ver), f"Version {ver} did not match major.minor.patch")

    def test_generated_xray_config_passes_real_xray_dry_run(self):
        xray_bin, _ = xray_runner.find_xray_bin()
        l_reality = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=reality&sni=example.com&pbk=ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU&sid=1234&type=tcp&fp=firefox#r"
        l_xhttp = "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&sni=example.com&type=xhttp&mode=packet-up&path=/xhttp#x"
        l_trojan = "trojan://pass@1.2.3.4:443?security=tls&sni=example.com&type=tcp#t"
        vm_dict = {"v":"2","ps":"v","add":"1.2.3.4","port":"443","id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"auto","net":"ws","type":"none","host":"example.com","path":"/ws","tls":"tls","sni":"example.com","fp":"firefox"}
        l_vmess = "vmess://" + base64.b64encode(json.dumps(vm_dict).encode()).decode()
        nodes = [collector.parse_node_info(l) for l in [l_reality, l_xhttp, l_trojan, l_vmess]]
        cfg, paired = xray_runner.build_xray_batch_config(nodes, 25000)
        self.assertEqual(len(paired), 4)
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cfg, f); tmp_path = f.name
        try:
            res = subprocess.run([xray_bin, "run", "-test", "-c", tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(res.returncode, 0, f"xray -test failed:\n{res.stderr}\n{res.stdout}")
        finally:
            if os.path.exists(tmp_path): os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
