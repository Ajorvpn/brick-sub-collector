"""Unit tests for scripts/iran_verify_publish.py (100% mocked, no network)."""

import asyncio
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scripts import iran_verify_publish as ivp  # noqa: E402
import collector  # noqa: E402


class _AsyncCM:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, *args):
        return False


class TestIranVerifyPublish(unittest.IsolatedAsyncioTestCase):
    def _node(self, idx: int, country: str = "DE", rtt: int = 100) -> collector.NodeInfo:
        ip = f"198.51.{idx}.1"
        link = f"vless://uuid-{idx}@{ip}:443?security=tls&sni=a.example&type=ws#n{idx}"
        n = collector.parse_node_info(link)
        n.iran_verified = True
        n.resolved_ip = ip
        n.country_code = country
        n.exit_country = country
        n.exit_ip = ip
        n.avg_latency_ms = rtt
        return n

    def test_negative_control_aborts_on_non_ir_or_error(self):
        fake_us = subprocess.CompletedProcess(["curl"], 0, stdout="ip=1.2.3.4\nloc=US\n", stderr="")
        with mock.patch("subprocess.run", return_value=fake_us):
            with self.assertRaises(ivp.NegativeControlError):
                ivp.verify_direct_iran_control("wlan0")

        fake_err = subprocess.CompletedProcess(["curl"], 28, stdout="", stderr="timeout")
        with mock.patch("subprocess.run", return_value=fake_err):
            with self.assertRaises(ivp.NegativeControlError):
                ivp.verify_direct_iran_control("wlan0")

        fake_ir = subprocess.CompletedProcess(["curl"], 0, stdout="ip=5.5.5.5\nloc=ir\n", stderr="")
        with mock.patch("subprocess.run", return_value=fake_ir):
            self.assertEqual(ivp.verify_direct_iran_control("wlan0"), "IR")

    def test_concurrency_clamped_and_shuffle_uses_seed(self):
        self.assertEqual(ivp.clamp_concurrency(0), 1)
        self.assertEqual(ivp.clamp_concurrency(2), 2)
        self.assertEqual(ivp.clamp_concurrency(99), 4)

    async def test_circuit_breaker_triggers_after_streak_and_resets_on_pass(self):
        nodes = [self._node(i) for i in range(12)]
        sleeps = []

        async def fake_sleep(dur):
            sleeps.append(dur)

        # First 5 fail (trigger breaker once), #6 passes (resets), #7-12 stay < 5? No: 6 fail -> 2nd trigger
        fail_set = {0, 1, 2, 3, 4, 6, 7, 8, 9, 10}

        async def fake_probe(session, port, node, **kwargs):
            idx = int(node.host.split(".")[2])
            if idx in fail_set:
                return (False, "step_a_timeout") if kwargs.get("return_reason") else False
            node.exit_country = "DE"
            node.avg_latency_ms = 120
            node.singbox_verified = True
            return (True, "ok") if kwargs.get("return_reason") else True

        with mock.patch.object(
            ivp,
            "_running_singbox_entries",
            side_effect=lambda b, batch, iface, **kw: _AsyncCM([(n, 10000 + i, {}) for i, n in enumerate(batch)]),
        ), mock.patch.object(
            collector, "_probe_singbox_port", side_effect=fake_probe
        ), mock.patch.object(
            ivp, "verify_direct_iran_control", return_value=("IR", 3.2)
        ) as ctrl_mock, mock.patch("asyncio.sleep", side_effect=fake_sleep):
            res = await ivp.probe_candidates_inside_iran(
                nodes,
                binary="/tmp/fake_sb",
                interface="wlan0",
                max_candidates=12,
                concurrency=99,  # clamps to 4
                jitter_min=1.0,
                jitter_max=2.0,
                circuit_breaker_streak=5,
                circuit_breaker_cooldown=33.0,
                seed=42,
            )

        self.assertGreaterEqual(res["circuit_breaker_triggers"], 1)
        self.assertIn(33.0, sleeps)
        for jitter in [s for s in sleeps if s != 33.0]:
            self.assertGreaterEqual(jitter, 1.0)
            self.assertLessEqual(jitter, 2.0)
        self.assertEqual(ctrl_mock.call_count, res["circuit_breaker_triggers"])
        self.assertEqual(res["failure_buckets"]["step_a_timeout"], 10)
        self.assertEqual(res["failure_buckets"]["ok"], 2)

    async def test_adaptive_breaker_short_cooldown_and_non_timeout_buckets_and_schema(self):
        args = ivp.build_arg_parser().parse_args([])
        self.assertEqual(args.trace_timeout, 6.0)
        self.assertEqual(args.payload_timeout, 9.0)
        self.assertEqual(args.connect_timeout, "4s")

        cfg = ivp.build_stage2_singbox_config([(self._node(1), 10000, {"type": "vless", "tag": "out_0"})], "wlan0")
        self.assertEqual(cfg["route"]["default_domain_resolver"], "dns-direct")
        self.assertEqual(cfg["dns"]["servers"][0]["detour"], "direct")

        nodes = [self._node(i) for i in range(6)]
        sleeps = []

        async def fake_sleep(d):
            sleeps.append(d)

        # First 5 nodes return step_a_timeout (fast direct RTT 0.4s -> 10.0s cooldown),
        # 6th returns step_a_blocked_loc (non-timeout -> does not trip breaker).
        async def fake_probe(session, port, node, **kwargs):
            idx = int(node.host.split(".")[2])
            if idx < 5:
                return (False, "step_a_timeout")
            return (False, "step_a_blocked_loc")

        with mock.patch.object(
            ivp,
            "_running_singbox_entries",
            side_effect=lambda b, batch, iface, **kw: _AsyncCM([(n, 10000 + i, {}) for i, n in enumerate(batch)]),
        ), mock.patch.object(
            collector, "_probe_singbox_port", side_effect=fake_probe
        ), mock.patch.object(
            ivp, "verify_direct_iran_control", return_value=("IR", 0.4)
        ), mock.patch("asyncio.sleep", side_effect=fake_sleep):
            res = await ivp.probe_candidates_inside_iran(
                nodes,
                binary="/tmp/fake_sb",
                interface="wlan0",
                max_candidates=6,
                concurrency=1,
                jitter_min=0.0,
                jitter_max=0.0,
                circuit_breaker_streak=5,
                circuit_breaker_cooldown=45.0,
                seed=7,
            )

        self.assertEqual(res["circuit_breaker_triggers"], 1)
        self.assertEqual(sleeps, [10.0])
        self.assertEqual(res["failure_buckets"], {"step_a_blocked_loc": 1, "step_a_timeout": 5})

    async def test_anti_zombie_step_d_drops_stalled_finalist(self):
        n_alive = self._node(1, country="NL", rtt=90)
        n_zombie = self._node(2, country="NL", rtt=110)

        async def fake_zombie_probe(session, port):
            return port == 10000

        sleeps = []

        async def fake_sleep(d):
            sleeps.append(d)

        with mock.patch.object(
            ivp,
            "_running_singbox_entries",
            return_value=_AsyncCM([(n_alive, 10000, {}), (n_zombie, 10001, {})]),
        ), mock.patch.object(
            ivp, "_probe_zombie_port", side_effect=fake_zombie_probe
        ), mock.patch("asyncio.sleep", side_effect=fake_sleep):
            passed, dropped = await ivp.verify_anti_zombie_finalists(
                "/tmp/fake_sb", [n_alive, n_zombie], "wlan0", hold_sec=15.0, concurrency=2
            )

        self.assertEqual(passed, [n_alive])
        self.assertEqual(dropped, 1)
        self.assertEqual(sleeps, [15.0])

    async def test_publish_requires_survivor_and_uses_http_proxy_without_leaking_token(self):
        tmp = tempfile.mkdtemp()
        try:
            with mock.patch.dict(os.environ, {"BRICK_SUB_PUSH_TOKEN": "tok-placeholder"}, clear=False):
                with self.assertRaises(RuntimeError):
                    await ivp.publish_via_survivor_proxy([], tmp, "/tmp/sb", "wlan0", "Ajorvpn/brick-sub-collector")

            survivor = self._node(1, country="NL", rtt=50)
            with open(os.path.join(tmp, "sub.txt"), "w", encoding="utf-8") as f:
                f.write("ZHVtbXk=")

            class _FakeTraceResp:
                status = 200

                async def __aenter__(self):
                    return self

                async def __aexit__(self, *a):
                    return False

                async def text(self, errors="replace"):
                    return "ip=203.0.113.5\nloc=NL\n"

            git_cmds = []

            def fake_subproc(cmd, **kwargs):
                git_cmds.append(cmd)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

            with mock.patch.dict(os.environ, {"BRICK_SUB_PUSH_TOKEN": "secret-tok-placeholder"}, clear=False), \
                 mock.patch.object(ivp, "_running_singbox_entries", return_value=_AsyncCM([(survivor, 23456, {})])), \
                 mock.patch("aiohttp.ClientSession.get", return_value=_FakeTraceResp()), \
                 mock.patch("subprocess.run", side_effect=fake_subproc):
                await ivp.publish_via_survivor_proxy(
                    [survivor], tmp, "/tmp/sb", "wlan0", "Ajorvpn/brick-sub-collector"
                )

            push_cmds = [c for c in git_cmds if "push" in c]
            self.assertEqual(len(push_cmds), 1)
            self.assertIn("http.proxy=http://127.0.0.1:23456", push_cmds[0])
            self.assertIn("https.proxy=http://127.0.0.1:23456", push_cmds[0])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
