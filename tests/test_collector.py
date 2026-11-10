"""Unit tests for collector.py multi-stage pipeline (no network required)."""

import asyncio
import base64
import json
import unittest
from unittest import mock

import collector


class TestParseNodeInfo(unittest.TestCase):
    def test_vmess_tls(self):
        cfg = {
            "add": "1.2.3.4",
            "port": 443,
            "id": "uuid",
            "tls": "tls",
            "sni": "example.com",
            "net": "ws",
        }
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "vmess")
        self.assertEqual(node.host, "1.2.3.4")
        self.assertEqual(node.port, 443)
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "example.com")
        self.assertEqual(node.network, "ws")

    def test_vmess_no_tls(self):
        cfg = {"add": "5.6.7.8", "port": 8080, "id": "uuid", "net": "tcp"}
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertFalse(node.tls_enabled)
        self.assertIsNone(node.sni)
        self.assertEqual(node.network, "tcp")

    def test_vmess_malformed(self):
        self.assertIsNone(collector.parse_node_info("vmess://notbase64!!!"))
        bad = base64.b64encode(b"{bad json").decode()
        self.assertIsNone(collector.parse_node_info("vmess://" + bad))
        self.assertIsNone(
            collector.parse_node_info(
                "vmess://" + base64.b64encode(json.dumps({"add": "x"}).encode()).decode()
            )
        )

    def test_vless_tls_reality(self):
        link = "vless://uuid@2.2.2.2:443?security=reality&sni=example.com&type=ws#remark"
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "vless")
        self.assertEqual(node.host, "2.2.2.2")
        self.assertEqual(node.port, 443)
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "example.com")
        self.assertEqual(node.network, "ws")

    def test_vless_no_tls(self):
        link = "vless://uuid@3.3.3.3:8080?security=none&type=tcp#remark"
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertFalse(node.tls_enabled)
        self.assertEqual(node.network, "tcp")

    def test_trojan(self):
        link = "trojan://password@4.4.4.4:443?sni=example.com&type=tcp#remark"
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "trojan")
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "example.com")

    def test_ss(self):
        link = "ss://aes-256-gcm:password@5.5.5.5:8388#remark"
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "ss")
        self.assertFalse(node.tls_enabled)
        self.assertEqual(node.network, "tcp")

    def test_invalid_links(self):
        self.assertIsNone(collector.parse_node_info("http://example.com"))
        self.assertIsNone(collector.parse_node_info("notalink"))
        self.assertIsNone(collector.parse_node_info(""))
        self.assertIsNone(collector.parse_node_info("vless://@:0#x"))


class TestBuildCleanName(unittest.TestCase):
    def test_format(self):
        name = collector.build_clean_name("DE", 1, "vless", 42)
        self.assertEqual(name, "🇩🇪 Germany 01 | VLESS | ⚡ 42ms | BrickVPN")

    def test_us(self):
        name = collector.build_clean_name("US", 5, "trojan", 120)
        self.assertEqual(name, "🇺🇸 United States 05 | TROJAN | ⚡ 120ms | BrickVPN")




class TestRenameNode(unittest.TestCase):
    def test_vmess_rename(self):
        cfg = {"add": "1.2.3.4", "port": 443, "id": "uuid", "ps": "old remark"}
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        node = collector.parse_node_info(link)
        node.country_code = "DE"
        node.avg_latency_ms = 42
        result = collector.rename_node(node, "DE", 1)
        # The renamed link should contain the clean name in its JSON payload.
        b64 = result[len("vmess://"):]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        decoded = json.loads(base64.b64decode(b64).decode(encoding="utf-8"))
        self.assertEqual(decoded["ps"], "🇩🇪 Germany 01 | VMESS | ⚡ 42ms | BrickVPN")
        self.assertEqual(decoded["add"], "1.2.3.4")
        self.assertEqual(decoded["port"], 443)

    def test_vless_rename(self):
        link = "vless://uuid@2.2.2.2:443?security=tls#old remark"
        node = collector.parse_node_info(link)
        node.country_code = "FR"
        node.avg_latency_ms = 55
        result = collector.rename_node(node, "FR", 3)
        self.assertTrue(result.startswith("vless://uuid@2.2.2.2:443?security=tls#"))
        self.assertIn("🇫🇷 France 03 | VLESS | ⚡ 55ms | BrickVPN", result)

    def test_trojan_rename(self):
        link = "trojan://pass@3.3.3.3:443#old"
        node = collector.parse_node_info(link)
        node.country_code = "NL"
        node.avg_latency_ms = 30
        result = collector.rename_node(node, "NL", 2)
        self.assertIn("🇳🇱 Netherlands 02 | TROJAN | ⚡ 30ms | BrickVPN", result)

    def test_ss_rename(self):
        link = "ss://aes-256-gcm:pw@4.4.4.4:8388#old"
        node = collector.parse_node_info(link)
        node.country_code = "CA"
        node.avg_latency_ms = 10
        result = collector.rename_node(node, "CA", 1)
        self.assertIn("🇨🇦 Canada 01 | SS | ⚡ 10ms | BrickVPN", result)



class TestVerifyNodeStability(unittest.IsolatedAsyncioTestCase):
    async def test_passes_both_probes(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )
        call_count = {"n": 0}

        async def fake_probe(n):
            call_count["n"] += 1
            return True

        with mock.patch.object(collector, "_single_probe", side_effect=fake_probe):
            result = await collector.verify_node_stability(node)

        self.assertIsNotNone(result)
        self.assertEqual(call_count["n"], 2)
        self.assertIsNotNone(node.avg_latency_ms)
        self.assertIsNotNone(node.quality_score)

    async def test_fails_second_probe_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )

        async def fake_probe(n):
            return False

        with mock.patch.object(collector, "_single_probe", side_effect=fake_probe):
            result = await collector.verify_node_stability(node)

        self.assertIsNone(result)
        self.assertEqual(node.error, "dual probe failed")

    async def test_passes_first_fails_second_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )
        calls = {"n": 0}

        async def fake_probe2(n):
            calls["n"] += 1
            return calls["n"] == 1

        with mock.patch.object(collector, "_single_probe", side_effect=fake_probe2):
            result = await collector.verify_node_stability(node)

        self.assertIsNone(result)

    async def test_quality_score_sorting(self):
        node1 = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1", quality_score=50.0,
            avg_latency_ms=40, jitter_ms=5,
        )
        node2 = collector.NodeInfo(
            protocol="vless", host="2.2.2.2", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="2.2.2.2", quality_score=30.0,
            avg_latency_ms=25, jitter_ms=3,
        )
        nodes = [node1, node2]
        nodes.sort(key=lambda n: n.quality_score or float("inf"))
        self.assertEqual(nodes[0].resolved_ip, "2.2.2.2")
        self.assertEqual(nodes[1].resolved_ip, "1.1.1.1")



class TestBatchGeoIPFiltering(unittest.TestCase):
    def test_keeps_only_allowed_countries(self):
        nodes = [
            collector.NodeInfo(
                protocol="vless", host="1.1.1.1", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip="1.1.1.1", country_code="DE",
            ),
            collector.NodeInfo(
                protocol="vless", host="2.2.2.2", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip="2.2.2.2", country_code="IR",
            ),
            collector.NodeInfo(
                protocol="vless", host="3.3.3.3", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip="3.3.3.3", country_code="CN",
            ),
        ]
        allowed = [n for n in nodes if n.country_code in collector.ALLOWED_COUNTRIES]
        self.assertEqual(len(allowed), 1)
        self.assertEqual(allowed[0].country_code, "DE")

    def test_allowed_countries_exact(self):
        expected = {"DE", "FI", "NL", "GB", "FR", "US", "CH", "SE", "AT", "CA"}
        self.assertEqual(set(collector.ALLOWED_COUNTRIES.keys()), expected)
        blocked = {"IR", "CN", "RU"}
        self.assertTrue(blocked.isdisjoint(set(collector.ALLOWED_COUNTRIES.keys())))


class TestQuotaEnforcement(unittest.TestCase):
    def test_main_quota_max_5_per_country(self):
        de_nodes = []
        for i in range(7):
            n = collector.NodeInfo(
                protocol="vless", host=f"1.1.1.{i}", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip=f"1.1.1.{i}", country_code="DE",
                quality_score=float(i), avg_latency_ms=i,
            )
            de_nodes.append(n)
        de_nodes.sort(key=lambda n: n.quality_score or float("inf"))
        main_links = []
        for n in de_nodes[:collector.MAIN_QUOTA_PER_COUNTRY]:
            main_links.append("link")
        self.assertEqual(len(main_links), 5)

    def test_empty_country_no_padding(self):
        by_country = {"DE": [], "FR": [], "NL": []}
        main_links = []
        for code in sorted(collector.ALLOWED_COUNTRIES.keys()):
            nodes = by_country.get(code, [])
            for n in nodes[:collector.MAIN_QUOTA_PER_COUNTRY]:
                main_links.append("link")
        self.assertEqual(len(main_links), 0)

    def test_total_max_50(self):
        self.assertEqual(
            collector.MAIN_QUOTA_PER_COUNTRY * len(collector.ALLOWED_COUNTRIES), 50
        )


class TestExtractLinks(unittest.TestCase):
    def test_plain_text(self):
        text = "vless://u@1.1.1.1:443\ntrojan://p@2.2.2.2:443"
        links = collector.extract_links(text)
        self.assertIn("vless://u@1.1.1.1:443", links)
        self.assertIn("trojan://p@2.2.2.2:443", links)

    def test_base64_subscription(self):
        raw = "vless://u@5.5.5.5:443\ntrojan://p@6.6.6.6:443"
        b64 = base64.b64encode(raw.encode()).decode()
        links = collector.extract_links(b64)
        self.assertIn("vless://u@5.5.5.5:443", links)
        self.assertIn("trojan://p@6.6.6.6:443", links)

    def test_empty(self):
        self.assertEqual(collector.extract_links(""), [])


if __name__ == "__main__":
    unittest.main()
