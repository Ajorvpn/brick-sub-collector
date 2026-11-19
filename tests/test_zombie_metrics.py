"""Unit tests for scripts/zombie_metrics.py."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts"))
)

import zombie_metrics


class TestZombieMetrics(unittest.TestCase):
    def test_healthy_60s_stream_passes(self):
        samples = [150.0] * 60
        res = zombie_metrics.evaluate_stream(samples, probe_40s_ok=True)
        self.assertTrue(res["passed"])
        self.assertEqual(res["reason"], "OK")
        self.assertEqual(res["m_early"], 150.0)
        self.assertEqual(res["m_late"], 150.0)
        self.assertEqual(res["decay"], 1.0)
        self.assertEqual(res["z_max"], 0)

    def test_slow_start_rejected(self):
        samples = [10.0] * 60
        res = zombie_metrics.evaluate_stream(samples, probe_40s_ok=True)
        self.assertFalse(res["passed"])
        self.assertEqual(res["reason"], "Zombie-Slow-Start(M_early<20KB/s)")
        self.assertLess(res["m_early"], 20.0)

    def test_died_30_to_60s_rejected(self):
        # m_early = 100.0, m_late = 5.0 (< 20.0)
        samples = [100.0] * 28 + [5.0] * 32
        res = zombie_metrics.evaluate_stream(samples, probe_40s_ok=True)
        self.assertFalse(res["passed"])
        self.assertEqual(res["reason"], "Zombie-Died-30to60s(M_late<20KB/s)")
        self.assertGreaterEqual(res["m_early"], 20.0)
        self.assertLess(res["m_late"], 20.0)

    def test_throttled_decay_ratio_rejected(self):
        # m_early = 100.0, m_late = 30.0 >= 20.0, decay = 0.30 < 0.45
        samples = [100.0] * 28 + [30.0] * 32
        res = zombie_metrics.evaluate_stream(samples, probe_40s_ok=True)
        self.assertFalse(res["passed"])
        self.assertEqual(res["reason"], "Zombie-Throttled(D<0.45)")
        self.assertEqual(res["m_early"], 100.0)
        self.assertEqual(res["m_late"], 30.0)
        self.assertLess(res["decay"], 0.45)

    def test_mid_stream_6s_stall_rejected(self):
        # 100 KB/s stream with a 6-second stall (0.0 KB/s) at indices 15..20
        samples = [100.0] * 15 + [0.0] * 6 + [100.0] * 39
        res = zombie_metrics.evaluate_stream(samples, probe_40s_ok=True)
        self.assertFalse(res["passed"])
        self.assertEqual(res["reason"], "Zombie-Stalled(Z_max>=6s)")
        self.assertGreaterEqual(res["z_max"], 6)

    def test_40s_concurrent_probe_failure_rejected(self):
        samples = [120.0] * 60
        res = zombie_metrics.evaluate_stream(samples, probe_40s_ok=False)
        self.assertFalse(res["passed"])
        self.assertEqual(res["reason"], "Zombie-40s-Probe-Failed")


if __name__ == "__main__":
    unittest.main()
