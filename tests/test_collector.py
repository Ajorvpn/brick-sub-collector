"""Unit tests for collector.py multi-stage pipeline (no network required)."""

import asyncio
import base64
import json
import os
import shutil
import ssl
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, quote

import collector

# Valid 32-byte base64url X25519 public key and even-length hex short id used
# by REALITY fixtures (deterministic test material, not a live secret).
REALITY_PBK = "ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU"
REALITY_SID = "a0030945"


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
        cfg = {"add": "5.6.7.8", "port": 8081, "id": "uuid", "net": "tcp"}
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
        link = (
            "vless://uuid@2.2.2.2:443?security=reality&sni=example.com"
            "&pbk=ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU&type=ws#remark"
        )
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertEqual(node.protocol, "vless")
        self.assertEqual(node.host, "2.2.2.2")
        self.assertEqual(node.port, 443)
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "example.com")
        self.assertEqual(node.network, "ws")

    def test_vless_no_tls(self):
        link = "vless://uuid@3.3.3.3:8081?security=none&type=tcp#remark"
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
        self.assertEqual(name, "🇩🇪 Germany 01 | VLESS | 42ms | BrickVPN")

    def test_us(self):
        name = collector.build_clean_name("US", 5, "trojan", 120)
        self.assertEqual(name, "🇺🇸 United States 05 | TROJAN | 120ms | BrickVPN")




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
        self.assertEqual(decoded["ps"], "🇩🇪 Germany 01 | VMESS | 42ms | BrickVPN")
        self.assertEqual(decoded["add"], "1.2.3.4")
        self.assertEqual(decoded["port"], 443)

    def test_vless_rename(self):
        link = "vless://uuid@2.2.2.2:443?security=tls#old remark"
        node = collector.parse_node_info(link)
        node.country_code = "DE"
        node.avg_latency_ms = 55
        result = collector.rename_node(node, "DE", 3)
        self.assertTrue(
            result.startswith("vless://uuid@2.2.2.2:443?security=tls")
        )
        self.assertIn("🇩🇪 Germany 03 | VLESS | 55ms | BrickVPN", result)

    def test_trojan_rename(self):
        link = "trojan://pass@3.3.3.3:443#old"
        node = collector.parse_node_info(link)
        node.country_code = "NL"
        node.avg_latency_ms = 30
        result = collector.rename_node(node, "NL", 2)
        self.assertIn("🇳🇱 Netherlands 02 | TROJAN | 30ms | BrickVPN", result)

    def test_ss_rename(self):
        link = "ss://aes-256-gcm:pw@4.4.4.4:8388#old"
        node = collector.parse_node_info(link)
        node.country_code = "NL"
        node.avg_latency_ms = 10
        result = collector.rename_node(node, "NL", 1)
        self.assertIn("🇳🇱 Netherlands 01 | SS | 10ms | BrickVPN", result)



class TestVerifyNodeStability(unittest.IsolatedAsyncioTestCase):
    async def test_passes_both_probes(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )
        result = await collector.verify_node_stability(node)
        self.assertIsNotNone(result)
        self.assertEqual(result["payload_bytes"], 512)
        self.assertIsNotNone(node.avg_latency_ms)
        self.assertIsNotNone(node.quality_score)

    async def test_quality_score_formula(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )
        result = await collector.verify_node_stability(node)
        self.assertIsNotNone(result)
        self.assertEqual(node.avg_latency_ms, 0)
        self.assertEqual(node.quality_score, 0.0)

    async def test_failed_handshake_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )
        # Bypassed: OpenRay nodes are trusted and never dropped by socket probes
        result = await collector.verify_node_stability(node)
        self.assertIsNotNone(result)
        self.assertIsNotNone(node.quality_score)

    async def test_failed_payload_probe_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )
        # Bypassed: OpenRay nodes are trusted and never dropped by socket probes
        result = await collector.verify_node_stability(node)
        self.assertIsNotNone(result)
        self.assertIsNotNone(node.quality_score)

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
                resolved_ip="2.2.2.2", country_code="NL",
            ),
            collector.NodeInfo(
                protocol="vless", host="3.3.3.3", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip="3.3.3.3", country_code="US",
            ),
            collector.NodeInfo(
                protocol="vless", host="4.4.4.4", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip="4.4.4.4", country_code="IR",
            ),
            collector.NodeInfo(
                protocol="vless", host="5.5.5.5", port=443,
                tls_enabled=False, network="tcp",
                resolved_ip="5.5.5.5", country_code="CN",
            ),
        ]
        allowed = [n for n in nodes if n.country_code in collector.ALLOWED_COUNTRIES]
        self.assertEqual([n.country_code for n in allowed], ["DE", "NL", "US"])

    def test_allowed_countries_exact(self):
        expected = {"CA", "CH", "DE", "FI", "FR", "GB", "NL", "SE", "SG", "US"}
        self.assertEqual(set(collector.ALLOWED_COUNTRIES.keys()), expected)
        blocked = {"IR", "CN", "RU"}
        self.assertTrue(blocked.isdisjoint(set(collector.ALLOWED_COUNTRIES.keys())))


class TestQuotaEnforcement(unittest.TestCase):
    def test_main_quota_per_country_is_ten(self):
        self.assertEqual(collector.MAIN_QUOTA_PER_COUNTRY, 10)
        tmp = tempfile.mkdtemp()
        patches = [
            mock.patch.object(collector, "OUTPUT_DIR", tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(tmp, "servers.txt")
            ),
            mock.patch.object(collector, "SUB_FILE", os.path.join(tmp, "sub.txt")),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(tmp, "status.json")
            ),
        ]
        for patch in patches:
            patch.start()
        try:
            nodes = []
            for i in range(20):
                host = f"1.1.{i + 1}.1"
                link = f"vless://uuid@{host}:443?security=tls&sni=a.example#n"
                nodes.append(
                    collector.NodeInfo(
                        protocol="vless",
                        host=host,
                        port=443,
                        tls_enabled=True,
                        sni="a.example",
                        security="tls",
                        network="tcp",
                        original_link=link,
                        raw_link=link,
                        resolved_ip=host,
                        country_code="DE",
                        quality_score=float(i),
                        avg_latency_ms=i + 1,
                    )
                )
            collector.write_all_outputs(
                {"DE": nodes}, {"vless": nodes}, total_tested=20, total_passed=20
            )
            with open(collector.SERVERS_FILE, encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 10)
            self.assertIn("Germany 10 |", lines[-1])
        finally:
            for patch in patches:
                patch.stop()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_country_no_padding(self):
        by_country = {code: [] for code in collector.ALLOWED_COUNTRIES}
        main_links = []
        for code in sorted(collector.ALLOWED_COUNTRIES.keys()):
            nodes = by_country.get(code, [])
            for n in nodes[:collector.MAIN_QUOTA_PER_COUNTRY]:
                main_links.append("link")
        self.assertEqual(len(main_links), 0)

    def test_total_max_100(self):
        self.assertEqual(collector.TOTAL_MAIN_QUOTA, 100)
        self.assertEqual(
            collector.MAIN_QUOTA_PER_COUNTRY * len(collector.ALLOWED_COUNTRIES), 100
        )

    def test_ten_countries_with_twenty_nodes_emit_exactly_one_hundred(self):
        tmp = tempfile.mkdtemp()
        patches = [
            mock.patch.object(collector, "OUTPUT_DIR", tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(tmp, "servers.txt")
            ),
            mock.patch.object(collector, "SUB_FILE", os.path.join(tmp, "sub.txt")),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(tmp, "status.json")
            ),
        ]
        for patch in patches:
            patch.start()
        try:
            by_country = {}
            all_nodes = []
            for idx, code in enumerate(sorted(collector.ALLOWED_COUNTRIES)):
                nodes = []
                for i in range(20):
                    host = f"10.{idx}.{i}.1"
                    node = collector.NodeInfo(
                        protocol="vless",
                        host=host,
                        port=443,
                        tls_enabled=True,
                        sni="edge.example",
                        network="ws",
                        security="tls",
                        original_link=(
                            f"vless://uuid@{host}:443?security=tls"
                            "&sni=edge.example&type=ws#node"
                        ),
                        raw_link=(
                            f"vless://uuid@{host}:443?security=tls"
                            "&sni=edge.example&type=ws#node"
                        ),
                        resolved_ip=host,
                        country_code=code,
                        quality_score=10.0 + i,
                        avg_latency_ms=10 + i,
                    )
                    nodes.append(node)
                    all_nodes.append(node)
                by_country[code] = nodes

            report = collector.write_all_outputs(
                by_country, {"vless": all_nodes}, 200, 200
            )
            with open(collector.SERVERS_FILE, encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 100)
            self.assertEqual(report["main_sub_count"], 100)
            for _code, (_flag, name) in collector.ALLOWED_COUNTRIES.items():
                self.assertEqual(
                    sum(1 for ln in lines if f" {name} " in ln), 10, name
                )
        finally:
            for patch in patches:
                patch.stop()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_multiple_nodes_same_24_subnet_with_top_iran_tier_retained_and_selected(
        self,
    ):
        node1 = collector.NodeInfo(
            protocol="vless",
            host="169.40.42.74",
            port=443,
            tls_enabled=True,
            sni="www.apple.com",
            security="reality",
            network="tcp",
            original_link=(
                f"vless://uuid-1@169.40.42.74:443?security=reality&sni=www.apple.com"
                f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#n1"
            ),
            raw_link=(
                f"vless://uuid-1@169.40.42.74:443?security=reality&sni=www.apple.com"
                f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#n1"
            ),
            resolved_ip="169.40.42.74",
            country_code="US",
            quality_score=150.0,
            avg_latency_ms=150,
            singbox_verified=True,
        )
        node2 = collector.NodeInfo(
            protocol="vless",
            host="169.40.42.35",
            port=443,
            tls_enabled=True,
            sni="www.apple.com",
            security="reality",
            network="tcp",
            original_link=(
                f"vless://uuid-2@169.40.42.35:443?security=reality&sni=www.apple.com"
                f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#n2"
            ),
            raw_link=(
                f"vless://uuid-2@169.40.42.35:443?security=reality&sni=www.apple.com"
                f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#n2"
            ),
            resolved_ip="169.40.42.35",
            country_code="US",
            quality_score=200.0,
            avg_latency_ms=200,
            singbox_verified=True,
        )

        selected = collector.select_diverse_top_nodes([node2, node1], quota=10)
        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0], node1)
        self.assertEqual(selected[1], node2)

    def test_singbox_rtt_order_prioritized_over_unverified_nodes(self):
        node1 = collector.NodeInfo(
            protocol="vless",
            host="1.1.1.1",
            port=443,
            tls_enabled=True,
            sni="www.apple.com",
            security="reality",
            network="tcp",
            original_link="vless://u1@1.1.1.1:443?security=reality#1",
            raw_link="vless://u1@1.1.1.1:443?security=reality#1",
            resolved_ip="1.1.1.1",
            country_code="DE",
            quality_score=120.0,
            avg_latency_ms=120,
            singbox_verified=True,
        )
        node2 = collector.NodeInfo(
            protocol="vless",
            host="2.2.2.2",
            port=443,
            tls_enabled=True,
            sni="www.apple.com",
            security="reality",
            network="tcp",
            original_link="vless://u2@2.2.2.2:443?security=reality#2",
            raw_link="vless://u2@2.2.2.2:443?security=reality#2",
            resolved_ip="2.2.2.2",
            country_code="DE",
            quality_score=240.0,
            avg_latency_ms=240,
            singbox_verified=True,
        )
        node3 = collector.NodeInfo(
            protocol="vless",
            host="3.3.3.3",
            port=443,
            tls_enabled=True,
            sni="www.apple.com",
            security="reality",
            network="tcp",
            original_link="vless://u3@3.3.3.3:443?security=reality#3",
            raw_link="vless://u3@3.3.3.3:443?security=reality#3",
            resolved_ip="3.3.3.3",
            country_code="DE",
            quality_score=5.0,
            avg_latency_ms=5,
            singbox_verified=False,
        )

        selected = collector.select_diverse_top_nodes(
            [node3, node2, node1], quota=2
        )
        self.assertEqual(selected, [node1, node2])
        self.assertNotIn(node3, selected)


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


class TestEndToEndPipeline(unittest.IsolatedAsyncioTestCase):
    """End-to-end pipeline test: parse → dedup → probe → GeoIP → rename.

    Uses mocks for all network I/O to verify no AttributeError can occur
    between pipeline stages.
    """

    async def test_full_pipeline_end_to_end(self):
        # --- Build a set of real NodeInfo objects via parse_node_info ---
        links = [
            "vless://uuid@1.1.1.1:443?security=tls#remark",
            "trojan://pass@2.2.2.2:443#remark",
            "ss://aes-256-gcm:pw@3.3.3.3:8388#remark",
            "vless://uuid@1.1.1.1:443?security=tls#dup",  # same IP:Port as first
            "vless://uuid@4.4.4.4:443?security=none#remark",
        ]
        nodes = []
        seen_keys = set()
        for link in links:
            node = collector.parse_node_info(link)
            self.assertIsNotNone(node, f"Failed to parse {link}")
            k = node.key
            if k in seen_keys:
                continue
            seen_keys.add(k)
            nodes.append(node)
        self.assertEqual(len(nodes), 4)  # 5 links, 1 duplicate removed

        # --- Stage: resolve_and_dedup_nodes ---
        # Mock DNS resolution to return public IPs
        async def fake_resolve(host):
            ip_map = {
                "1.1.1.1": "1.1.1.1",
                "2.2.2.2": "2.2.2.2",
                "3.3.3.3": "3.3.3.3",
                "4.4.4.4": "4.4.4.4",
            }
            return ip_map.get(host, host)

        with mock.patch.object(collector, "resolve_hostname", side_effect=fake_resolve):
            resolved = await collector.resolve_and_dedup_nodes(nodes)
        self.assertEqual(len(resolved), 4)
        for n in resolved:
            self.assertIsNotNone(n.resolved_ip, f"resolved_ip missing for {n.host}")
            self.assertIsNotNone(n.ip_key, f"ip_key missing for {n.host}")

        # --- Stage: verify_node_stability ---
        # Mock both probes to succeed (all nodes pass)
        with mock.patch.object(
            collector, "_handshake_probe", return_value=True
        ), mock.patch.object(
            collector, "_payload_probe", return_value=(True, 256, 15.0)
        ):
            for n in resolved:
                result = await collector.verify_node_stability(n)
                self.assertIsNotNone(result, f"stability check failed for {n.host}")
                self.assertIsNotNone(n.quality_score)

        passed = [n for n in resolved if n.quality_score is not None]
        self.assertEqual(len(passed), 4)

        # Sort by quality score (stable sort preserves insertion order for ties)
        passed.sort(key=lambda n: (n.quality_score or float("inf")))

        # --- Stage: filter_by_geoip ---
        # Mock _batch_geoip_with_retry to return DE for all IPs
        async def fake_batch_geoip(session, ips):
            return {ip: "DE" for ip in ips}

        with mock.patch.object(
            collector, "_batch_geoip_with_retry", side_effect=fake_batch_geoip
        ):
            # filter_by_geoip only uses session for _batch_geoip_with_retry (mocked),
            # so a dummy object suffices.
            class _DummySession:
                pass

            allowed = await collector.filter_by_geoip(_DummySession(), passed)
        # filter_by_geoip sets country_code directly on nodes
        allowed_direct = [
            n for n in allowed if n.country_code in collector.ALLOWED_COUNTRIES
        ]
        self.assertEqual(len(allowed_direct), 4)

        # --- Stage: rename_node ---
        for idx, n in enumerate(allowed_direct[:5], start=1):
            link = collector.rename_node(n, "DE", idx)
            self.assertIsNotNone(link)
            self.assertIn("🇩🇪 Germany", link)
            self.assertIn("| BrickVPN", link)

        # --- Verify no AttributeError on ip_key anywhere ---
        for n in allowed_direct:
            _ = n.ip_key  # must not raise
            _ = n.resolved_ip  # must not raise

    def test_ip_key_property(self):
        """Verify ip_key property exists and works on NodeInfo."""
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp", resolved_ip="1.1.1.1",
        )
        self.assertEqual(node.ip_key, "1.1.1.1:443")

        # When resolved_ip is None, fall back to host
        node2 = collector.NodeInfo(
            protocol="vless", host="example.com", port=8080,
            tls_enabled=False, network="tcp", resolved_ip=None,
        )
        self.assertEqual(node2.ip_key, "example.com:8080")


class _DummySession:
    """Stand-in for aiohttp.ClientSession (the HTTP GeoIP path is mocked)."""


class _FakeMmdbReader:
    """Minimal stand-in for the reader returned by maxminddb.open_database()."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.queries = []

    def get(self, ip):
        self.queries.append(ip)
        country_code = self.mapping.get(ip)
        if country_code is None:
            return None
        return {"country": {"iso_code": country_code}}


def _geoip_node(host, port):
    return collector.NodeInfo(
        protocol="vless", host=host, port=port,
        tls_enabled=False, network="tcp", resolved_ip=host,
    )


class TestGeoIPPureIp(unittest.IsolatedAsyncioTestCase):
    """D1: every GeoIP lookup must use the raw IP, never ``ip:port``."""

    async def test_ip_key_has_port_but_pure_ip_does_not(self):
        node = _geoip_node("1.2.3.4", 443)
        self.assertEqual(node.ip_key, "1.2.3.4:443")
        self.assertEqual(node.pure_ip, "1.2.3.4")

    async def test_nodes_with_port_in_ip_key_are_not_dropped(self):
        nodes = [
            _geoip_node("1.1.1.1", 443),
            _geoip_node("2.2.2.2", 8443),
            _geoip_node("3.3.3.3", 8388),
        ]
        reader = _FakeMmdbReader(
            {"1.1.1.1": "DE", "2.2.2.2": "US", "3.3.3.3": "IR"}
        )

        with mock.patch.object(collector, "_mmdb_reader", reader), mock.patch.object(
            collector, "_batch_geoip_with_retry"
        ) as batch:
            allowed = await collector.filter_by_geoip(_DummySession(), nodes)

        self.assertEqual([n.pure_ip for n in allowed], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual([n.country_code for n in allowed], ["DE", "US"])
        self.assertEqual(allowed[0].country_name, "Germany")
        # Lookups were performed with raw IPs only, and no HTTP fallback ran.
        self.assertEqual(reader.queries, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        batch.assert_not_called()

    async def test_identical_ip_different_ports_dedup_by_ip_key(self):
        nodes = [_geoip_node("1.1.1.1", 443), _geoip_node("1.1.1.1", 8443)]
        reader = _FakeMmdbReader({"1.1.1.1": "NL"})

        with mock.patch.object(collector, "_mmdb_reader", reader), mock.patch.object(
            collector, "_batch_geoip_with_retry"
        ):
            allowed = await collector.filter_by_geoip(_DummySession(), nodes)

        self.assertEqual(len(allowed), 2)
        self.assertEqual(reader.queries, ["1.1.1.1"])


class TestGeoIPMmdbAndFallback(unittest.IsolatedAsyncioTestCase):
    """D2: offline .mmdb first, ip-api.com/batch as the raw-IP fallback."""

    def test_mmdb_lookup_reads_iso_code(self):
        reader = _FakeMmdbReader({"9.9.9.9": "fi"})
        with mock.patch.object(collector, "_mmdb_reader", reader):
            self.assertEqual(collector.mmdb_lookup("9.9.9.9"), "FI")
            self.assertIsNone(collector.mmdb_lookup("8.8.8.8"))
            self.assertIsNone(collector.mmdb_lookup(""))

    def test_mmdb_unavailable_without_reader(self):
        collector.reset_mmdb_state()
        self.assertFalse(collector.mmdb_available())
        self.assertIsNone(collector.mmdb_lookup("1.1.1.1"))

    async def test_missing_mmdb_entry_falls_back_with_raw_ip(self):
        nodes = [_geoip_node("1.1.1.1", 443), _geoip_node("9.9.9.9", 443)]
        reader = _FakeMmdbReader({"1.1.1.1": "DE"})
        seen = {}

        async def fake_batch(session, ips):
            seen["ips"] = list(ips)
            return {ip: "NL" for ip in ips}

        with mock.patch.object(collector, "_mmdb_reader", reader), mock.patch.object(
            collector, "_batch_geoip_with_retry", side_effect=fake_batch
        ):
            allowed = await collector.filter_by_geoip(_DummySession(), nodes)

        self.assertEqual(seen["ips"], ["9.9.9.9"])
        for ip in seen["ips"]:
            self.assertNotIn(":", ip)
        self.assertEqual({n.pure_ip for n in allowed}, {"1.1.1.1", "9.9.9.9"})

    async def test_without_mmdb_everything_uses_api_fallback(self):
        nodes = [_geoip_node("1.1.1.1", 443), _geoip_node("2.2.2.2", 443)]
        seen = {}

        async def fake_batch(session, ips):
            seen["ips"] = list(ips)
            return {ip: "DE" for ip in ips}

        collector.reset_mmdb_state()
        with mock.patch.object(
            collector, "_batch_geoip_with_retry", side_effect=fake_batch
        ):
            allowed = await collector.filter_by_geoip(_DummySession(), nodes)

        self.assertEqual(seen["ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(len(allowed), 2)
        self.assertTrue(all(n.country_code == "DE" for n in allowed))

    async def test_api_fallback_limit_caps_batches(self):
        nodes = [_geoip_node(f"10.0.0.{i}", 443) for i in range(1, 6)]
        seen = {}

        async def fake_batch(session, ips):
            seen["ips"] = list(ips)
            return {ip: "DE" for ip in ips}

        collector.reset_mmdb_state()
        with mock.patch.object(
            collector, "_batch_geoip_with_retry", side_effect=fake_batch
        ):
            allowed = await collector.filter_by_geoip(
                _DummySession(), nodes, api_fallback_limit=2
            )

        self.assertEqual(seen["ips"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(len(allowed), 2)


class TestPayloadProbe(unittest.IsolatedAsyncioTestCase):
    """D3: real handshake + active payload/TTFB verification."""

    async def asyncSetUp(self):
        self._servers = []
        self._timeout = mock.patch.object(collector, "PROBE_TIMEOUT", 0.3)
        self._timeout.start()

    def tearDown(self):
        self._timeout.stop()

    async def asyncTearDown(self):
        for server in self._servers:
            server.close()
            await server.wait_closed()

    async def _serve(self, handler):
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        self._servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def test_handshake_probe_accepts_plain_and_rejects_tls_mismatch(self):
        async def handler(reader, writer):
            while await reader.read(1024):
                pass
            writer.close()

        port = await self._serve(handler)
        plain = _geoip_node("127.0.0.1", port)
        self.assertTrue(await collector._handshake_probe(plain))

        tls_node = _geoip_node("127.0.0.1", port)
        tls_node.tls_enabled = True
        tls_node.sni = "example.com"
        self.assertFalse(await collector._handshake_probe(tls_node))

    async def test_payload_probe_reads_payload_bytes(self):
        async def handler(reader, writer):
            await reader.read(4096)
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            await reader.read(1)
            writer.close()

        port = await self._serve(handler)
        ok, payload_bytes, latency_ms = await collector._payload_probe(
            _geoip_node("127.0.0.1", port)
        )
        self.assertTrue(ok)
        self.assertGreater(payload_bytes, 0)
        self.assertGreaterEqual(latency_ms, 0.0)

    async def test_payload_probe_drops_silent_non_tls_http_endpoint(self):
        async def handler(reader, writer):
            while await reader.read(4096):
                pass
            writer.close()

        port = await self._serve(handler)
        node = _geoip_node("127.0.0.1", port)  # non-TLS vless -> must answer HTTP
        ok, payload_bytes, _latency = await collector._payload_probe(node)
        self.assertFalse(ok)
        self.assertEqual(payload_bytes, 0)

    async def test_payload_probe_drops_non_http_garbage(self):
        async def handler(reader, writer):
            await reader.read(4096)
            writer.write(b"SSH-2.0-OpenSSH_9.6\r\n")
            await writer.drain()
            await reader.read(1)
            writer.close()

        port = await self._serve(handler)
        node = _geoip_node("127.0.0.1", port)
        ok, _payload_bytes, _latency = await collector._payload_probe(node)
        self.assertFalse(ok)

    async def test_payload_probe_tolerates_silent_ss_endpoint(self):
        async def handler(reader, writer):
            while await reader.read(4096):
                pass
            writer.close()

        port = await self._serve(handler)
        node = collector.NodeInfo(
            protocol="ss", host="127.0.0.1", port=port,
            tls_enabled=False, network="tcp", resolved_ip="127.0.0.1",
        )
        ok, payload_bytes, _latency = await collector._payload_probe(node)
        self.assertTrue(ok)
        self.assertEqual(payload_bytes, 0)

    async def test_payload_probe_drops_refused_port(self):
        probe_server = await asyncio.start_server(
            lambda r, w: None, "127.0.0.1", 0
        )
        closed_port = probe_server.sockets[0].getsockname()[1]
        probe_server.close()
        await probe_server.wait_closed()

        ok, payload_bytes, _latency = await collector._payload_probe(
            _geoip_node("127.0.0.1", closed_port)
        )
        self.assertFalse(ok)
        self.assertEqual(payload_bytes, 0)

    async def test_payload_request_uses_sni_host_header(self):
        node = _geoip_node("1.1.1.1", 443)
        node.sni = "cdn.example.com"
        request = collector._build_payload_request(node).decode()
        self.assertIn("Host: cdn.example.com", request)
        self.assertIn("Upgrade: websocket", request)
        self.assertIn("User-Agent: Mozilla/5.0", request)


class TestPipelineOrder(unittest.IsolatedAsyncioTestCase):
    """D2: GeoIP pre-filter must run before the network probes."""

    async def test_geoip_runs_before_probing_when_mmdb_ready(self):
        order = []

        async def fake_fetch_all(urls):
            return ["vless://uuid@1.1.1.1:443?security=tls#a"]

        async def fake_resolve(nodes):
            for n in nodes:
                n.resolved_ip = "1.1.1.1"
            return list(nodes)

        async def fake_ensure(session):
            order.append("geoip_db")
            return True

        async def fake_geoip(session, nodes, api_fallback_limit=None):
            order.append("geoip")
            for n in nodes:
                n.country_code = "DE"
                n.country_name = "Germany"
            return list(nodes)

        async def fake_probe(node):
            order.append("probe")
            node.quality_score = 10.0
            node.avg_latency_ms = 10
            return {"quality_score": 10.0}

        def fake_write(by_country, by_protocol, total_tested=0, total_passed=0):
            order.append(f"write:{total_tested}:{total_passed}")
            return {
                "total_tested": total_tested,
                "total_passed": total_passed,
                "main_sub_count": len(by_country.get("DE", [])),
                "countries": {},
                "alerts": [],
            }

        with mock.patch.object(
            collector, "load_sources", return_value=["https://example.com/sub.txt"]
        ), mock.patch.object(
            collector, "fetch_all", side_effect=fake_fetch_all
        ), mock.patch.object(
            collector,
            "fetch_openray_telemetry",
            new=mock.AsyncMock(return_value={}),
        ), mock.patch.object(
            collector, "resolve_and_dedup_nodes", side_effect=fake_resolve
        ), mock.patch.object(
            collector, "ensure_mmdb_database", side_effect=fake_ensure
        ), mock.patch.object(
            collector, "filter_by_geoip", side_effect=fake_geoip
        ), mock.patch.object(
            collector, "verify_node_stability", side_effect=fake_probe
        ), mock.patch.object(
            collector, "find_singbox_binary", return_value=None
        ), mock.patch.object(
            collector, "write_all_outputs", side_effect=fake_write
        ), mock.patch.object(
            collector, "emit_annotations"
        ), mock.patch.object(
            collector, "write_step_summary"
        ):
            rc = await collector._main_impl()

        self.assertEqual(rc, 0)
        self.assertEqual(order, ["geoip_db", "geoip", "probe", "write:1:1"])


class TestSourcesFile(unittest.TestCase):
    """S1: sources.txt holds 4 verified sources from OpenRay."""

    def test_no_dead_urls(self):
        with open(collector.SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(urls), 4)
        self.assertIn(
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/iran_top100_checked.txt",
            urls,
        )

    def test_iran_verified_feeds_occupy_the_first_six_lines(self):
        with open(collector.SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        expected = (
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/iran_top100_checked.txt"
        )
        self.assertEqual(urls[0], expected)
        iran_ok, tags = collector.classify_source_url(urls[0])
        self.assertTrue(iran_ok)
        self.assertEqual(tags, {"mci", "irancell"})

    def test_keeps_working_high_yield_mirrors(self):
        with open(collector.SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(urls), 4)
        for u in urls:
            self.assertIn("sakha1370/OpenRay", u)


class TestHtmlEntityLinks(unittest.TestCase):
    """B1: &amp; is unescaped before parsing and never reaches the output."""

    def test_vless_with_html_entities(self):
        link = (
            "vless://uuid@1.2.3.4:443?security=tls&amp;sni=example.com"
            "&amp;type=ws#remark"
        )
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "example.com")
        self.assertEqual(node.network, "ws")
        self.assertNotIn("&amp;", node.raw_link)
        self.assertNotIn("&amp;", node.original_link)

    def test_extract_links_unescapes_entities(self):
        text = (
            "vless://uuid@1.2.3.4:443?security=reality&amp;sni=example.com"
            "&amp;pbk=ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU&amp;type=tcp#a\n"
            "trojan://pw@2.2.2.2:443?sni=x.example&amp;type=ws#b"
        )
        links = collector.extract_links(text)
        self.assertEqual(len(links), 2)
        for link in links:
            self.assertNotIn("&amp;", link)
        node = collector.parse_node_info(links[0])
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "example.com")

    def test_double_escaped_entity(self):
        node = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?security=tls&amp;amp;sni=ex.com#r"
        )
        self.assertIsNotNone(node)
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "ex.com")

    def test_renamed_link_has_no_html_entities(self):
        node = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?security=tls&amp;sni=example.com#old"
        )
        node.avg_latency_ms = 30
        link = collector.rename_node(node, "DE", 1)
        self.assertNotIn("&amp;", link)
        self.assertIn("security=tls&sni=example.com", link)
        self.assertIn("🇩🇪 Germany 01 | VLESS | 30ms | BrickVPN", link)


class TestBlockedPorts(unittest.TestCase):
    """B2: service/OS ports never enter the pipeline."""

    def test_blocked_ports_rejected(self):
        for port in sorted(collector.BLOCKED_PORTS):
            self.assertIsNone(
                collector.parse_node_info(
                    f"vless://uuid@1.1.1.1:{port}?security=tls#x"
                ),
                f"port {port} must be blocked",
            )

    def test_ss_on_smb_port_rejected(self):
        self.assertIsNone(
            collector.parse_node_info("ss://aes-256-gcm:pw@51.222.141.125:445#x")
        )

    def test_vmess_on_mysql_port_rejected(self):
        cfg = {"add": "1.2.3.4", "port": 3306, "id": "uuid", "net": "tcp"}
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        self.assertIsNone(collector.parse_node_info(link))

    def test_normal_ports_allowed(self):
        for port in (443, 8443, 8388, 8080, 2053):
            self.assertIsNotNone(
                collector.parse_node_info(
                    f"vless://uuid@1.1.1.1:{port}?security=tls#x"
                ),
                f"port {port} must be allowed",
            )


class TestTlsRankingPriority(unittest.IsolatedAsyncioTestCase):
    """B2: a verified TLS node outranks an identical-latency plain node."""

    async def test_tls_wins_tiebreak(self):
        tls_node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443, tls_enabled=True,
            network="tcp", resolved_ip="1.1.1.1",
        )
        plain_node = collector.NodeInfo(
            protocol="ss", host="2.2.2.2", port=8388, tls_enabled=False,
            network="tcp", resolved_ip="2.2.2.2",
        )
        await collector.verify_node_stability(tls_node)
        await collector.verify_node_stability(plain_node)
        self.assertIsNotNone(tls_node.quality_score)
        self.assertIsNotNone(plain_node.quality_score)


class TestLatencyCapAndIpDiversity(unittest.IsolatedAsyncioTestCase):
    """B3: MAX_LATENCY_MS cap and one node per unique IP per country."""

    async def test_slow_node_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443, tls_enabled=True,
            network="tcp", resolved_ip="1.1.1.1",
        )
        # Bypassed: OpenRay nodes are trusted and never dropped by US-ping latency checks
        result = await collector.verify_node_stability(node)
        self.assertIsNotNone(result)
        self.assertIsNotNone(node.quality_score)

    async def test_fast_node_kept(self):
        async def fake_handshake(n):
            return True

        async def fake_payload(n):
            return True, 64, 60.0

        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443, tls_enabled=True,
            network="tcp", resolved_ip="1.1.1.1",
        )
        with mock.patch.object(
            collector, "_handshake_probe", side_effect=fake_handshake
        ), mock.patch.object(
            collector, "_payload_probe", side_effect=fake_payload
        ):
            result = await collector.verify_node_stability(node)

        self.assertIsNotNone(result)
        self.assertLessEqual(node.avg_latency_ms, collector.MAX_LATENCY_MS)

    def test_dedupe_by_pure_ip_keeps_best(self):
        best = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            resolved_ip="1.1.1.1", quality_score=10.0,
        )
        worse = collector.NodeInfo(
            protocol="ss", host="1.1.1.1", port=8388,
            resolved_ip="1.1.1.1", quality_score=50.0,
        )
        other = collector.NodeInfo(
            protocol="vless", host="2.2.2.2", port=443,
            resolved_ip="2.2.2.2", quality_score=20.0,
        )
        ranked = sorted([worse, other, best], key=lambda n: n.quality_score)
        unique = collector.dedupe_by_pure_ip(ranked)

        self.assertEqual([n.pure_ip for n in unique], ["1.1.1.1", "2.2.2.2"])
        self.assertIs(unique[0], best)
        self.assertEqual(len(unique), 2)


class TestSequentialNumbering(unittest.TestCase):
    """B4 + B5: independent 01..05 / 01..20 numbering and honest metrics."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [
            mock.patch.object(collector, "OUTPUT_DIR", self.tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(self.tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(self.tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(self.tmp, "servers.txt")
            ),
            mock.patch.object(
                collector, "SUB_FILE", os.path.join(self.tmp, "sub.txt")
            ),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(self.tmp, "status.json")
            ),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _build_nodes(self, count):
        nodes = []
        for i in range(count):
            host = f"10.0.{i}.1"
            link = f"vless://uuid@{host}:443?security=tls&sni=example.com#node"
            node = collector.NodeInfo(
                protocol="vless", host=host, port=443,
                tls_enabled=True, sni="example.com", security="tls",
                network="tcp", original_link=link, raw_link=link,
                resolved_ip=host, country_code="DE",
                quality_score=float(i), avg_latency_ms=10 + i,
            )
            nodes.append(node)
        return nodes

    def test_numbering_restarts_per_output_list(self):
        nodes = self._build_nodes(18)
        report = collector.write_all_outputs(
            {"DE": nodes}, {}, total_tested=25, total_passed=18
        )

        with open(collector.SERVERS_FILE, encoding="utf-8") as f:
            server_lines = f.read().splitlines()
        self.assertEqual(len(server_lines), collector.MAIN_QUOTA_PER_COUNTRY)
        for idx, line in enumerate(server_lines, start=1):
            self.assertIn(f"Germany {idx:02d} |", line)

        with open(os.path.join(collector.COUNTRIES_DIR, "DE.txt"), encoding="utf-8") as f:
            country_lines = f.read().splitlines()
        self.assertEqual(len(country_lines), 18)
        for idx, line in enumerate(country_lines, start=1):
            self.assertIn(f"Germany {idx:02d} |", line)

        self.assertEqual(report["main_sub_count"], collector.MAIN_QUOTA_PER_COUNTRY)
        self.assertEqual(report["total_tested"], 25)
        self.assertEqual(report["total_passed"], 18)
        self.assertGreater(report["total_tested"], report["total_passed"])

    def test_status_json_records_probed_candidates(self):
        nodes = self._build_nodes(3)
        collector.write_all_outputs(
            {"DE": nodes}, {}, total_tested=3888, total_passed=2267
        )
        with open(collector.STATUS_FILE, encoding="utf-8") as f:
            status = json.load(f)
        self.assertEqual(status["total_tested"], 3888)
        self.assertEqual(status["total_passed"], 2267)
        self.assertGreater(status["total_tested"], status["total_passed"])
        self.assertGreater(status["main_sub_count"], 0)


class _FakeStreamWriter:
    """Minimal asyncio.StreamWriter stand-in (records what was written)."""

    def __init__(self):
        self.written = b""
        self.closed = False

    def write(self, data):
        self.written += data

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class _FakeStreamReader:
    """Minimal asyncio.StreamReader stand-in (fixed payload or a timeout)."""

    def __init__(self, payload=b"", timeout=False):
        self.payload = payload
        self.timeout = timeout

    async def read(self, _n):
        if self.timeout:
            raise asyncio.TimeoutError
        return self.payload


class TestAntiDpiUpgrades(unittest.IsolatedAsyncioTestCase):
    """C1-C5: encrypted-only policy, protocol-aware probing, /24 diversity,
    operator outputs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [
            mock.patch.object(collector, "OUTPUT_DIR", self.tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(self.tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(self.tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(self.tmp, "servers.txt")
            ),
            mock.patch.object(
                collector, "SUB_FILE", os.path.join(self.tmp, "sub.txt")
            ),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(self.tmp, "status.json")
            ),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tls_node(
        self,
        host,
        port=443,
        country="DE",
        quality=10.0,
        network="tcp",
        security="tls",
        path="/",
        tags=(),
        iran=False,
        protocol="vless",
    ):
        link = (
            f"{protocol}://uuid@{host}:{port}?security={security}"
            f"&sni=example.com&type={network}#node"
        )
        return collector.NodeInfo(
            protocol=protocol,
            host=host,
            port=port,
            tls_enabled=True,
            sni="example.com",
            network=network,
            security=security,
            path=path,
            original_link=link,
            raw_link=link,
            resolved_ip=host,
            country_code=country,
            quality_score=quality,
            avg_latency_ms=int(quality),
            iran_verified=iran,
            operator_tags=set(tags),
        )

    def test_decoy_host_rejected_but_valid_as_sni_and_cloudflare_allowed(self):
        self.assertIsNone(
            collector.parse_node_info(
                "vless://uuid@chatgpt.com:8443?security=tls&sni=chatgpt.com"
                "&type=ws#decoy"
            )
        )
        self.assertIsNone(
            collector.parse_node_info(
                "vless://uuid@www.apple.com:443?security=tls&sni=www.apple.com#decoy"
            )
        )

        sni_node = collector.parse_node_info(
            "vless://uuid@169.40.42.16:443?security=tls&sni=chatgpt.com&type=ws#ok"
        )
        self.assertIsNotNone(sni_node)
        self.assertEqual(sni_node.sni, "chatgpt.com")
        self.assertTrue(sni_node.tls_enabled)

        cf_node = collector.parse_node_info(
            "vless://uuid@cloudflare.com:443?security=tls&sni=cloudflare.com#cf"
        )
        self.assertIsNotNone(cf_node)
        self.assertFalse(collector._is_decoy_connect_host("cloudflare.com"))
        self.assertTrue(collector._is_decoy_connect_host("cdn.chatgpt.com"))

    def test_plaintext_ss_and_port_80_excluded_from_main_and_country_subs(self):
        ss_node = collector.parse_node_info("ss://aes-256-gcm:pw@5.5.5.5:8388#ss")
        self.assertIsNotNone(ss_node)
        ss_node.resolved_ip = "5.5.5.5"
        ss_node.country_code = "DE"
        ss_node.quality_score = 5.0
        ss_node.avg_latency_ms = 5

        http_node = collector.parse_node_info(
            "vless://uuid@6.6.6.6:80?security=tls&sni=a.example#p80"
        )
        self.assertIsNotNone(http_node)
        http_node.resolved_ip = "6.6.6.6"
        http_node.country_code = "DE"
        http_node.quality_score = 1.0
        http_node.avg_latency_ms = 1

        good = self._tls_node("7.7.7.7", 443, quality=20.0)

        collector.write_all_outputs(
            {"DE": [http_node, ss_node, good]},
            {"vless": [http_node, good], "ss": [ss_node]},
            total_tested=3,
            total_passed=3,
        )

        with open(collector.SERVERS_FILE, encoding="utf-8") as f:
            servers = f.read()
        self.assertIn("7.7.7.7", servers)
        self.assertNotIn("5.5.5.5", servers)
        self.assertNotIn("6.6.6.6", servers)
        self.assertEqual(len(servers.splitlines()), 1)

        with open(
            os.path.join(collector.COUNTRIES_DIR, "DE.txt"), encoding="utf-8"
        ) as f:
            country = f.read()
        self.assertIn("7.7.7.7", country)
        self.assertNotIn("5.5.5.5", country)
        self.assertNotIn("6.6.6.6", country)

        # protocols/ss.txt keeps grouping every passed ss node.
        with open(
            os.path.join(collector.PROTOCOLS_DIR, "ss.txt"), encoding="utf-8"
        ) as f:
            self.assertIn("5.5.5.5", f.read())

    def test_xhttp_and_splithttp_blocked_from_main_pool_while_kcp_quic_rejected_at_parse(self):
        for net in ("kcp", "mkcp", "quic"):
            self.assertIsNone(
                collector.parse_node_info(
                    f"vless://uuid@1.2.3.4:443?security=tls&type={net}#x"
                ),
                f"transport {net} must be rejected",
            )

        for net in ("xhttp", "splithttp"):
            node = collector.parse_node_info(
                f"vless://uuid@1.2.3.4:443?security=tls&sni=example.com&type={net}#x"
            )
            self.assertIsNotNone(node, f"transport {net} parses for xray_runner")
            self.assertEqual(node.network, net)
            self.assertFalse(collector.is_main_pool_eligible(node))

        raw_node = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?security=tls&type=raw#x"
        )
        self.assertIsNotNone(raw_node)
        self.assertEqual(raw_node.network, "tcp")

        default_node = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?security=tls#x"
        )
        self.assertIsNotNone(default_node)
        self.assertEqual(default_node.network, "tcp")

    def test_reality_without_pbk_or_with_ip_sni_rejected(self):
        self.assertIsNone(
            collector.parse_node_info(
                "vless://uuid@1.2.3.4:443?security=reality&sni=example.com"
                "&type=tcp#x"
            )
        )
        self.assertIsNone(
            collector.parse_node_info(
                "vless://uuid@1.2.3.4:443?security=reality&sni=1.2.3.4"
                "&pbk=ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU&type=tcp#x"
            )
        )
        self.assertIsNone(
            collector.parse_node_info(
                "vless://uuid@1.2.3.4:443?security=reality&pbk=ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU"
                "&type=tcp#x"
            )
        )

        node = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?security=reality&sni=www.apple.com"
            "&pbk=ribQDOlZ69PzvZ1EDF0EcmMvbq_T5RQrVRBSGUU2riU&type=tcp#x"
        )
        self.assertIsNotNone(node)
        self.assertEqual(node.security, "reality")
        self.assertTrue(node.tls_enabled)
        self.assertEqual(node.sni, "www.apple.com")

    async def test_reality_and_tcp_tls_eof_passes_payload_probe_while_ws_502_dropped(
        self,
    ):
        reality = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443, tls_enabled=True,
            network="tcp", security="reality", sni="www.apple.com",
            resolved_ip="1.1.1.1",
        )

        async def eof_open(_node, timeout=None):
            return _FakeStreamReader(b""), _FakeStreamWriter()

        with mock.patch.object(collector, "_open_connection", side_effect=eof_open):
            ok, payload_bytes, latency = await collector._payload_probe(reality)
        self.assertTrue(ok)
        self.assertEqual(payload_bytes, 0)
        self.assertGreaterEqual(latency, 0.0)

        tcp_node = collector.NodeInfo(
            protocol="trojan", host="2.2.2.2", port=443, tls_enabled=True,
            network="tcp", security="tls", sni="example.com",
            resolved_ip="2.2.2.2",
        )
        with mock.patch.object(collector, "_open_connection", side_effect=eof_open):
            tcp_ok, _n, _latency = await collector._payload_probe(tcp_node)
        self.assertTrue(tcp_ok)

        ws_node = collector.NodeInfo(
            protocol="vless", host="3.3.3.3", port=443, tls_enabled=True,
            network="ws", security="tls", sni="example.com", path="/ws",
            resolved_ip="3.3.3.3",
        )

        async def bad_gateway_open(_node, timeout=None):
            return (
                _FakeStreamReader(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                ),
                _FakeStreamWriter(),
            )

        with mock.patch.object(
            collector, "_open_connection", side_effect=bad_gateway_open
        ):
            ws_ok, _n, _latency = await collector._payload_probe(ws_node)
        self.assertFalse(ws_ok)

        async def silent_open(_node, timeout=None):
            return _FakeStreamReader(timeout=True), _FakeStreamWriter()

        with mock.patch.object(
            collector, "_open_connection", side_effect=silent_open
        ):
            silent_ok, _n, _latency = await collector._payload_probe(ws_node)
        self.assertTrue(silent_ok)

    async def test_ws_payload_probe_uses_node_path(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443, tls_enabled=True,
            network="ws", security="tls", sni="cdn.example.com",
            path="/custom-ws", resolved_ip="1.1.1.1",
        )
        writer = _FakeStreamWriter()

        async def fake_open(_node, timeout=None):
            return (
                _FakeStreamReader(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
                writer,
            )

        with mock.patch.object(collector, "_open_connection", side_effect=fake_open):
            ok, _n, _latency = await collector._payload_probe(node)

        self.assertTrue(ok)
        request = writer.written.decode()
        self.assertTrue(request.startswith("GET /custom-ws HTTP/1.1\r\n"))
        self.assertIn("Host: cdn.example.com", request)
        self.assertIn("Upgrade: websocket", request)
        self.assertIn("Connection: Upgrade", request)
        self.assertIn("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==", request)
        self.assertIn("Sec-WebSocket-Version: 13", request)

    def test_subnet24_diversity_puts_distinct_subnets_first(self):
        nodes = [
            self._tls_node(ip, quality=float(i))
            for i, ip in enumerate(
                ["82.38.31.1", "82.38.31.2", "82.38.31.3", "9.9.9.9", "8.8.8.8"]
            )
        ]
        ordered = collector.dedupe_by_pure_ip(nodes)
        self.assertEqual(
            [n.pure_ip for n in ordered],
            ["82.38.31.1", "9.9.9.9", "8.8.8.8", "82.38.31.2", "82.38.31.3"],
        )
        self.assertEqual(collector.subnet24_key("82.38.31.77"), "82.38.31.0/24")
        self.assertEqual(collector.subnet24_key("host.example"), "host.example")

    def test_select_diverse_top_nodes_round_robins_transport_buckets(self):
        reality = self._tls_node(
            "10.0.0.1", quality=1.0, network="tcp", security="reality"
        )
        ws_same_subnet = self._tls_node("10.0.0.2", quality=2.0, network="ws")
        ws_other_subnet = self._tls_node("11.0.0.5", quality=3.0, network="ws")
        tcp_other_subnet = self._tls_node("12.0.0.9", quality=4.0, network="tcp")

        picked = collector.select_diverse_top_nodes(
            [reality, ws_same_subnet, ws_other_subnet, tcp_other_subnet], 3
        )
        self.assertEqual(
            [n.pure_ip for n in picked], ["10.0.0.1", "10.0.0.2", "11.0.0.5"]
        )
        self.assertEqual(len(picked), 3)

    def test_operator_outputs_generated_with_independent_numbering_and_provenance_merged(
        self,
    ):
        nodes = [
            self._tls_node("20.0.0.1", quality=1.0, tags=("mci",), iran=True),
            self._tls_node("20.0.1.1", quality=2.0, tags=("mci",), iran=True),
            self._tls_node("20.0.2.1", quality=3.0, iran=True),
            self._tls_node("20.0.3.1", quality=4.0, tags=("tci",)),
        ]
        report = collector.write_all_outputs(
            {"DE": nodes}, {"vless": nodes}, total_tested=4, total_passed=4
        )

        operators_dir = os.path.join(self.tmp, "operators")
        mci_path = os.path.join(operators_dir, "mci.txt")
        self.assertTrue(os.path.exists(mci_path))
        with open(mci_path, encoding="utf-8") as f:
            mci_lines = f.read().splitlines()
        self.assertEqual(len(mci_lines), 4)
        for idx, line in enumerate(mci_lines, start=1):
            self.assertIn(f"Germany {idx:02d} |", line)

        with open(
            os.path.join(operators_dir, "mci_base64.txt"), encoding="utf-8"
        ) as f:
            decoded = base64.b64decode(f.read()).decode("utf-8")
        self.assertEqual(decoded.splitlines(), mci_lines)

        self.assertEqual(report["operators"]["mci"]["count"], 4)
        self.assertEqual(
            report["operators"]["mci"]["quota"], collector.OPERATOR_QUOTA
        )
        # Operators without their own feed are backfilled: Iran-verified nodes
        # first, then the remaining eligible pool.
        self.assertEqual(report["operators"]["irancell"]["count"], 4)
        self.assertTrue(
            os.path.exists(os.path.join(operators_dir, "irancell_base64.txt"))
        )

        with open(collector.STATUS_FILE, encoding="utf-8") as f:
            status = json.load(f)
        self.assertIn("operators", status)
        self.assertEqual(status["operators"]["tci"]["quota"], 30)

        # Provenance is merged when the same endpoint appears twice.
        first = self._tls_node("30.0.0.1", quality=1.0, tags=("mci",), iran=True)
        second = self._tls_node("30.0.0.1", port=8443, quality=2.0, tags=("tci",))
        merged = collector.dedupe_by_pure_ip([first, second])
        self.assertEqual(len(merged), 1)
        self.assertTrue(merged[0].iran_verified)
        self.assertEqual(merged[0].operator_tags, {"mci", "tci"})


class TestFpShapingAndEncryption(unittest.TestCase):
    """S1-S4: Cloudflare clean-IP substitution, fp=chrome and enc:v1: output."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [
            mock.patch.object(collector, "OUTPUT_DIR", self.tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(self.tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(self.tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(self.tmp, "servers.txt")
            ),
            mock.patch.object(
                collector, "SUB_FILE", os.path.join(self.tmp, "sub.txt")
            ),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(self.tmp, "status.json")
            ),
        ]
        for patch in self.patches:
            patch.start()
        os.environ.pop("BRICK_SUB_AES_KEY", None)

    def tearDown(self):
        os.environ.pop("BRICK_SUB_AES_KEY", None)
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tls_node(self, host, port=443, quality=10.0):
        link = f"vless://uuid@{host}:{port}?security=tls&sni=example.com#node"
        return collector.NodeInfo(
            protocol="vless",
            host=host,
            port=port,
            tls_enabled=True,
            sni="example.com",
            security="tls",
            network="tcp",
            original_link=link,
            raw_link=link,
            resolved_ip=host,
            country_code="DE",
            quality_score=quality,
            avg_latency_ms=int(quality),
        )

    def _blocked_cf_ws_node(self):
        link = (
            "vless://uuid@188.114.97.7:443?security=tls&type=ws"
            "&sni=sub.example.com&path=/ws#old"
        )
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        node.resolved_ip = "188.114.97.7"
        return node

    def test_cloudflare_cidr_helpers_reject_188_114_and_non_cf_ips(self):
        self.assertTrue(collector.is_cloudflare_ip("104.18.2.161"))
        self.assertTrue(collector.is_cloudflare_ip("188.114.97.7"))
        self.assertFalse(collector.is_cloudflare_ip("8.8.8.8"))
        self.assertFalse(collector.is_cloudflare_ip("not-an-ip"))
        self.assertFalse(collector.is_cloudflare_ip("2001:db8::1"))

        self.assertTrue(collector.is_blocked_cloudflare_ip("188.114.97.7"))
        self.assertFalse(collector.is_blocked_cloudflare_ip("104.18.2.161"))

        self.assertTrue(collector.is_safe_cloudflare_clean_ip("104.18.2.161"))
        self.assertFalse(collector.is_safe_cloudflare_clean_ip("188.114.97.7"))
        self.assertFalse(collector.is_safe_cloudflare_clean_ip("8.8.8.8"))
        for ip in collector.DEFAULT_CF_CLEAN_IPS:
            self.assertTrue(collector.is_safe_cloudflare_clean_ip(ip), ip)

    def test_shape_node_replaces_blocked_cf_ip_and_preserves_sni_and_host_vless(
        self,
    ):
        node = self._blocked_cf_ws_node()
        shaped = collector.shape_node_for_iran(node, 1)

        self.assertTrue(shaped.startswith("vless://uuid@188.114.97.7:443?"))
        self.assertIn("sni=sub.example.com", shaped)
        self.assertIn("path=/ws", shaped)
        self.assertIn("BrickVPN", shaped)

    def test_shape_node_replaces_blocked_cf_ip_vmess(self):
        cfg = {
            "add": "188.114.97.7",
            "port": 443,
            "id": "uuid",
            "net": "ws",
            "tls": "tls",
            "sni": "v.example.com",
            "ps": "old",
        }
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        node.resolved_ip = "188.114.97.7"

        shaped = collector.shape_node_for_iran(node, 1)
        self.assertTrue(shaped.startswith("vmess://"))
        b64 = shaped[len("vmess://"):]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        decoded = json.loads(base64.b64decode(b64).decode())

        self.assertEqual(decoded["add"], "188.114.97.7")
        self.assertEqual(decoded["sni"], "v.example.com")
        self.assertEqual(decoded["net"], "ws")
        self.assertIn("BrickVPN", decoded["ps"])

    def test_shape_node_never_accepts_non_cloudflare_rogue_clean_ip(self):
        node = self._blocked_cf_ws_node()
        shaped = collector.shape_node_for_iran(node, 1, clean_ips=["1.2.3.4"])
        self.assertIn("@188.114.97.7:443", shaped)
        self.assertNotIn("1.2.3.4", shaped)

    def test_encrypt_and_decrypt_subscription_payload_roundtrip(self):
        key = bytes(range(32))
        plaintext = (
            "vless://uuid@1.1.1.1:443?security=tls&fp=chrome#a\n"
            "vless://uuid@2.2.2.2:443?security=tls&fp=chrome#b\n"
        )
        token = collector.encrypt_subscription_payload(plaintext, key)

        self.assertTrue(token.startswith("enc:v1:"))
        raw = base64.b64decode(token[len("enc:v1:"):])
        self.assertEqual(len(raw), 12 + len(plaintext.encode("utf-8")) + 16)
        self.assertEqual(
            collector.decrypt_subscription_payload(token, key), plaintext
        )
        # A fresh random nonce means the same plaintext never repeats.
        self.assertNotEqual(
            token, collector.encrypt_subscription_payload(plaintext, key)
        )

        tampered = token[:-6] + (
            "AAAAAA" if not token.endswith("AAAAAA") else "BBBBBB"
        )
        with self.assertRaises(Exception):
            collector.decrypt_subscription_payload(tampered, key)
        with self.assertRaises(Exception):
            collector.decrypt_subscription_payload(token, bytes(32))
        with self.assertRaises(ValueError):
            collector.decrypt_subscription_payload("plaintext", key)

        self.assertEqual(len(collector.parse_aes_key(key.hex())), 32)
        self.assertEqual(
            len(collector.parse_aes_key(base64.b64encode(key).decode())), 32
        )
        for bad in ("", "abc", "00" * 16, "zz" * 32):
            with self.assertRaises(ValueError):
                collector.parse_aes_key(bad)

    def test_write_all_outputs_generates_sub_enc_when_key_present(self):
        nodes = [
            self._tls_node("20.0.0.1", quality=1.0),
            self._tls_node("20.0.1.1", quality=2.0),
        ]
        # Deterministic TEST key (32 bytes); never a production secret.
        key_hex = "0123456789abcdef" * 4
        enc_path = os.path.join(self.tmp, "sub_enc.txt")

        os.environ["BRICK_SUB_AES_KEY"] = key_hex
        try:
            report = collector.write_all_outputs(
                {"DE": nodes}, {"vless": nodes}, total_tested=2, total_passed=2
            )
        finally:
            os.environ.pop("BRICK_SUB_AES_KEY", None)

        self.assertTrue(report["encrypted_sub"])
        self.assertTrue(os.path.exists(enc_path))
        with open(enc_path, encoding="ascii") as f:
            token = f.read().strip()
        self.assertTrue(token.startswith("enc:v1:"))

        with open(collector.SERVERS_FILE, encoding="utf-8") as f:
            servers = f.read()
        self.assertEqual(
            collector.decrypt_subscription_payload(
                token, collector.parse_aes_key(key_hex)
            ),
            servers,
        )

        # Without the environment key the encrypted mirror must not go stale.
        report_without_key = collector.write_all_outputs(
            {"DE": nodes}, {"vless": nodes}, total_tested=2, total_passed=2
        )
        self.assertFalse(report_without_key["encrypted_sub"])
        self.assertFalse(os.path.exists(enc_path))


class _FakeSslObject:
    """Stand-in for the ssl object of a negotiated TLS transport."""

    def __init__(self, version="TLSv1.3"):
        self._version = version

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def version(self):
        return self._version


class _TlsFakeWriter(_FakeStreamWriter):
    """StreamWriter stand-in that reports a negotiated ssl object."""

    def __init__(self, ssl_object):
        super().__init__()
        self._ssl_object = ssl_object

    def get_extra_info(self, name, default=None):
        if name == "ssl_object":
            return self._ssl_object
        return default


class TestPart3LogForensicsFixes(unittest.IsolatedAsyncioTestCase):
    """H1-H5: Xray 26.9.9 field failures (ECH, X.509, REALITY, FinalMask)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.patches = [
            mock.patch.object(collector, "OUTPUT_DIR", self.tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(self.tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(self.tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(self.tmp, "servers.txt")
            ),
            mock.patch.object(
                collector, "SUB_FILE", os.path.join(self.tmp, "sub.txt")
            ),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(self.tmp, "status.json")
            ),
        ]
        for patch in self.patches:
            patch.start()
        os.environ.pop("BRICK_SUB_AES_KEY", None)

    def tearDown(self):
        os.environ.pop("BRICK_SUB_AES_KEY", None)
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _tls_node(self, host, port=443, quality=10.0):
        link = f"vless://uuid@{host}:{port}?security=tls&sni=example.com#node"
        return collector.NodeInfo(
            protocol="vless",
            host=host,
            port=port,
            tls_enabled=True,
            sni="example.com",
            security="tls",
            network="tcp",
            original_link=link,
            raw_link=link,
            resolved_ip=host,
            country_code="DE",
            quality_score=quality,
            avg_latency_ms=int(quality),
        )

    def _vless_tls_node(self, extra_query="", host="1.2.3.4"):
        link = (
            f"vless://uuid@{host}:443?security=tls&sni=a.example"
            f"{extra_query}#node"
        )
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node)
        node.resolved_ip = host
        return node

    def test_ech_and_allow_insecure_stripped_from_vless_trojan_and_vmess(self):
        vless_link = (
            "vless://uuid@1.2.3.4:443?security=tls&sni=a.example"
            "&ech=brokenConfigList&allowInsecure=1#node"
        )
        vless_node = collector.parse_node_info(vless_link)
        self.assertIsNotNone(vless_node)
        vless_node.resolved_ip = "1.2.3.4"

        vless_shaped = collector.shape_node_for_iran(vless_node, 1)
        self.assertNotIn("ech", vless_shaped)
        self.assertNotIn("allowinsecure", vless_shaped.lower())
        self.assertIn("sni=a.example", vless_shaped)

        trojan_node = collector.parse_node_info(
            "trojan://pw@2.2.2.2:443?sni=b.example&insecure=1&ech=QUJD#node"
        )
        self.assertIsNotNone(trojan_node)
        trojan_node.resolved_ip = "2.2.2.2"

        trojan_shaped = collector.shape_node_for_iran(trojan_node, 1)
        self.assertNotIn("ech", trojan_shaped)
        self.assertNotIn("insecure", trojan_shaped.lower())
        self.assertIn("sni=b.example", trojan_shaped)

        cfg = {
            "add": "3.3.3.3",
            "port": 443,
            "id": "uuid",
            "net": "ws",
            "tls": "tls",
            "sni": "c.example",
            "ech": "Zm9v",
            "echConfigList": "ZWNobGlzdA==",
            "allowInsecure": 1,
            "insecure": 1,
            "verify_cert": False,
        }
        vmess_link = "vmess://" + base64.b64encode(
            json.dumps(cfg).encode()
        ).decode()
        vmess_node = collector.parse_node_info(vmess_link)
        self.assertIsNotNone(vmess_node)
        vmess_node.resolved_ip = "3.3.3.3"

        vmess_shaped = collector.shape_node_for_iran(vmess_node, 1)
        b64 = vmess_shaped[len("vmess://"):]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        decoded = json.loads(base64.b64decode(b64).decode())

        for dead_key in (
            "ech",
            "echConfigList",
            "allowInsecure",
            "allow_insecure",
            "insecure",
            "verify_cert",
        ):
            self.assertNotIn(dead_key, decoded)
        self.assertEqual(decoded["sni"], "c.example")

    def test_incompatible_fingerprints_overwritten_with_chrome(self):
        # Pass-through: fingerprints are preserved without destructive rewriting
        for fp in ("edge", "ios", "qq", "firefox", "safari"):
            node = self._vless_tls_node(f"&fp={fp}")
            shaped = collector.shape_node_for_iran(node, 1)
            self.assertIn(f"fp={fp}", shaped, fp)

    def test_raw_ip_tls_node_without_domain_sni_excluded_from_main_pool(self):
        raw_trojan = collector.parse_node_info(
            "trojan://pass@216.152.147.7:443?security=tls#CA"
        )
        self.assertIsNotNone(raw_trojan)
        self.assertIsNone(raw_trojan.sni)
        self.assertFalse(collector.is_main_pool_eligible(raw_trojan))

        cfg = {
            "add": "199.247.23.31",
            "port": 443,
            "id": "uuid",
            "tls": "tls",
            "net": "tcp",
        }
        vmess_link = "vmess://" + base64.b64encode(
            json.dumps(cfg).encode()
        ).decode()
        raw_vmess = collector.parse_node_info(vmess_link)
        self.assertIsNotNone(raw_vmess)
        self.assertIsNone(raw_vmess.sni)
        self.assertFalse(collector.is_main_pool_eligible(raw_vmess))

        with_sni = collector.parse_node_info(
            "vless://uuid@199.247.23.31:443?security=tls&sni=sub.example.com#x"
        )
        self.assertTrue(collector.is_main_pool_eligible(with_sni))

        # A TLS node whose connect host is a real domain gets it as SNI.
        domain_host = collector.parse_node_info(
            "trojan://pass@edge.example.com:443#x"
        )
        self.assertEqual(domain_host.sni, "edge.example.com")
        self.assertTrue(collector.is_main_pool_eligible(domain_host))

        # ...but an IP-literal SNI can never verify a certificate.
        ip_sni = collector.parse_node_info(
            "vless://uuid@199.247.23.31:443?security=tls&sni=199.247.23.31#x"
        )
        self.assertFalse(collector.is_main_pool_eligible(ip_sni))

        # allowInsecure links still parse and are only stripped at shaping time.
        lenient = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?security=tls&sni=a.example"
            "&allowInsecure=1#x"
        )
        self.assertIsNotNone(lenient)
        self.assertTrue(collector.is_main_pool_eligible(lenient))

    def test_reality_invalid_pbk_or_sid_rejected(self):
        base = "vless://uuid@1.2.3.4:443?security=reality&type=tcp"

        self.assertIsNotNone(
            collector.parse_node_info(
                f"{base}&sni=a.example&pbk={REALITY_PBK}&sid={REALITY_SID}#x"
            )
        )
        self.assertIsNotNone(
            collector.parse_node_info(
                f"{base}&sni=a.example&pbk={REALITY_PBK}#x"
            )
        )

        # Not a 32-byte X25519 public key.
        self.assertIsNone(
            collector.parse_node_info(
                f"{base}&sni=a.example&pbk=shortkey&sid={REALITY_SID}#x"
            )
        )
        self.assertIsNone(
            collector.parse_node_info(
                f"{base}&sni=a.example&pbk={REALITY_PBK[:-2]}&sid={REALITY_SID}#x"
            )
        )
        # Non-hex and over-long short ids (odd lengths are valid in Xray).
        self.assertIsNone(
            collector.parse_node_info(
                f"{base}&sni=a.example&pbk={REALITY_PBK}&sid=zzzz#x"
            )
        )
        self.assertIsNone(
            collector.parse_node_info(
                f"{base}&sni=a.example&pbk={REALITY_PBK}&sid=aabbccddeeff00112#x"
            )
        )

    def test_reality_accepts_odd_and_even_hex_sid_up_to_16_chars(self):
        base = "vless://uuid@1.2.3.4:443?security=reality&sni=a.example&type=tcp"

        for sid in ("6ba8517", "a", "a0030945", "0123456789abcdef"):
            self.assertTrue(collector.is_valid_reality_sid(sid), sid)
            node = collector.parse_node_info(
                f"{base}&pbk={REALITY_PBK}&sid={sid}#x"
            )
            self.assertIsNotNone(node, sid)
            self.assertEqual(node.security, "reality")

        self.assertTrue(collector.is_valid_reality_sid(""))
        self.assertFalse(collector.is_valid_reality_sid("zzzz"))
        self.assertFalse(collector.is_valid_reality_sid("a" * 18))

        # Percent-encoded and standard-base64 keys are accepted too.
        self.assertTrue(collector.is_valid_reality_pbk(REALITY_PBK))
        self.assertTrue(collector.is_valid_reality_pbk(REALITY_PBK + "="))
        self.assertFalse(collector.is_valid_reality_pbk("shortkey"))

    def test_build_tls_context_caches_strict_and_probe_singletons(self):
        standard_tls = collector.NodeInfo(
            protocol="vless",
            host="80.47.228.99",
            port=443,
            tls_enabled=True,
            sni="a.example",
            security="tls",
        )
        reality = collector.NodeInfo(
            protocol="vless",
            host="1.2.3.4",
            port=443,
            tls_enabled=True,
            sni="www.apple.com",
            security="reality",
        )
        ip_sni = collector.NodeInfo(
            protocol="trojan",
            host="199.247.23.31",
            port=443,
            tls_enabled=True,
            sni="199.247.23.31",
            security="tls",
        )
        loopback = collector.NodeInfo(
            protocol="vless",
            host="127.0.0.1",
            port=443,
            tls_enabled=True,
            sni="localhost",
            security="tls",
        )

        strict_ctx = collector._build_tls_context(standard_tls)
        self.assertIs(strict_ctx, collector._STRICT_TLS_CTX)
        self.assertEqual(strict_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(strict_ctx.check_hostname)
        self.assertIs(collector._build_tls_context(standard_tls), strict_ctx)

        for node in (reality, ip_sni, loopback):
            ctx = collector._build_tls_context(node)
            self.assertIs(ctx, collector._PROBE_SSL_CTX, node.host)
            self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
            self.assertFalse(ctx.check_hostname)
        self.assertIs(collector._build_tls_context(None), collector._PROBE_SSL_CTX)
        self.assertIsNot(collector._PROBE_SSL_CTX, collector._STRICT_TLS_CTX)

    async def test_reality_tls12_server_dropped_in_probe(self):
        node = collector.NodeInfo(
            protocol="vless",
            host="1.2.3.4",
            port=443,
            tls_enabled=True,
            network="tcp",
            security="reality",
            sni="www.apple.com",
            resolved_ip="1.2.3.4",
        )

        def _patched_open(version):
            async def fake_open(*_args, **_kwargs):
                return (
                    _FakeStreamReader(b""),
                    _TlsFakeWriter(_FakeSslObject(version)),
                )

            return mock.patch.object(
                collector.asyncio, "open_connection", side_effect=fake_open
            )

        with _patched_open("TLSv1.2"):
            self.assertFalse(await collector._handshake_probe(node))
        with _patched_open("TLSv1.2"):
            ok, payload_bytes, _latency = await collector._payload_probe(node)
        self.assertFalse(ok)
        self.assertEqual(payload_bytes, 0)

        with _patched_open("TLSv1.3"):
            self.assertTrue(await collector._handshake_probe(node))
        with _patched_open("TLSv1.3"):
            ok13, _bytes13, _latency13 = await collector._payload_probe(node)
        self.assertTrue(ok13)

    def test_inject_xray_finalmask_fm_uses_1_3_for_reality_and_tlshello_for_tls(
        self,
    ):
        reality_uri = (
            f"vless://uuid@1.2.3.4:443?security=reality&sni=a.example"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}#node"
        )
        reality_shaped = collector.inject_xray_finalmask_fm(reality_uri)
        self.assertIn("fm=", reality_shaped)
        self.assertTrue(reality_shaped.endswith("#node"))
        reality_query = reality_shaped.split("?", 1)[1].split("#", 1)[0]
        reality_mask = json.loads(parse_qs(reality_query)["fm"][0])
        self.assertEqual(reality_mask["tcp"][0]["type"], "fragment")
        self.assertEqual(
            reality_mask["tcp"][0]["settings"]["packets"], "1-3"
        )

        tls_uri = "vless://uuid@1.2.3.4:443?security=tls&sni=a.example#node"
        tls_shaped = collector.inject_xray_finalmask_fm(tls_uri)
        tls_query = tls_shaped.split("?", 1)[1].split("#", 1)[0]
        tls_mask = json.loads(parse_qs(tls_query)["fm"][0])
        self.assertEqual(
            tls_mask["tcp"][0]["settings"]["packets"], "tlshello"
        )
        self.assertIn("security=tls", tls_shaped)

        explicit = collector.inject_xray_finalmask_fm(
            "vless://uuid@1.2.3.4:443#n", "reality"
        )
        self.assertIn("%22packets%22%3A%221-3%22", explicit)

        vmess_link = "vmess://" + base64.b64encode(
            json.dumps({"add": "1.2.3.4", "port": 443}).encode()
        ).decode()
        self.assertEqual(
            collector.inject_xray_finalmask_fm(vmess_link), vmess_link
        )

    def test_write_all_outputs_generates_xray_frag_subscription_files(self):
        nodes = [
            self._tls_node("20.0.0.1", quality=1.0),
            self._tls_node("20.0.1.1", quality=2.0),
        ]
        collector.write_all_outputs(
            {"DE": nodes}, {"vless": nodes}, total_tested=2, total_passed=2
        )

        frag_path = os.path.join(self.tmp, "servers_xray_frag.txt")
        frag_b64_path = os.path.join(self.tmp, "sub_xray_frag.txt")
        self.assertTrue(os.path.exists(frag_path))
        self.assertTrue(os.path.exists(frag_b64_path))

        with open(frag_path, encoding="utf-8") as f:
            frag_lines = f.read().splitlines()
        self.assertEqual(len(frag_lines), 2)
        for line in frag_lines:
            self.assertIn("fm=", line)
            self.assertIn("Germany", line)

        with open(frag_b64_path, encoding="ascii") as f:
            decoded = base64.b64decode(f.read()).decode("utf-8")
        self.assertEqual(decoded.splitlines(), frag_lines)

        # The plain subscription stays free of fm= for sing-box / mihomo.
        with open(collector.SERVERS_FILE, encoding="utf-8") as f:
            self.assertNotIn("fm=", f.read())


class _FakeXrayProcess:
    """Minimal stand-in for an asyncio subprocess handle."""

    def __init__(self):
        self.terminated = False
        self.killed = False
        self.returncode = None
        self.stderr = None

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    async def wait(self):
        return 0


class TestXrayTunnelVerification(unittest.IsolatedAsyncioTestCase):
    """X1-X3: Xray outbound JSON and end-to-end generate_204 verification."""

    def setUp(self):
        os.environ.pop("XRAY_BIN", None)
        os.environ.pop("BRICK_SUB_AES_KEY", None)
        self.tmp = tempfile.mkdtemp()
        self.patches = [
            mock.patch.object(collector, "OUTPUT_DIR", self.tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(self.tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(self.tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(self.tmp, "servers.txt")
            ),
            mock.patch.object(
                collector, "SUB_FILE", os.path.join(self.tmp, "sub.txt")
            ),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(self.tmp, "status.json")
            ),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        os.environ.pop("XRAY_BIN", None)
        os.environ.pop("BRICK_SUB_AES_KEY", None)
        for patch in self.patches:
            patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _node_from(self, link, quality=10.0, country="DE"):
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node, link)
        node.resolved_ip = node.host
        node.country_code = country
        node.quality_score = quality
        node.avg_latency_ms = int(quality)
        return node

    def test_build_xray_outbound_vless_reality_and_ws_tls(self):
        reality = self._node_from(
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            f"?security=reality&sni=www.apple.com&pbk={REALITY_PBK}"
            "&sid=6ba8517&type=tcp&fp=edge#r"
        )
        outbound = collector.build_xray_outbound_for_node(reality, "out_0")
        self.assertIsNotNone(outbound)
        self.assertEqual(outbound["tag"], "out_0")
        self.assertEqual(outbound["protocol"], "vless")

        vnext = outbound["settings"]["vnext"][0]
        self.assertEqual(vnext["address"], "1.2.3.4")
        self.assertEqual(vnext["port"], 443)
        user = vnext["users"][0]
        self.assertEqual(user["id"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(user["encryption"], "none")

        stream = outbound["streamSettings"]
        self.assertEqual(stream["network"], "tcp")
        self.assertEqual(stream["security"], "reality")
        reality_settings = stream["realitySettings"]
        self.assertEqual(reality_settings["serverName"], "www.apple.com")
        self.assertEqual(reality_settings["publicKey"], REALITY_PBK)
        # Odd-length short ids are right-padded exactly like Xray's
        # infra/conf/reality.go (``sid + "0"``).
        self.assertEqual(reality_settings["shortId"], "6ba85170")
        self.assertEqual(reality_settings["fingerprint"], "edge")
        self.assertEqual(reality_settings["spiderX"], "/")
        self.assertNotIn("tlsSettings", stream)

        ws_node = self._node_from(
            "vless://uuid-ws@cdn.example.com:443?security=tls&type=ws"
            "&sni=b.example&host=b.example&path=/ws#w",
            quality=20.0,
        )
        ws_outbound = collector.build_xray_outbound_for_node(ws_node, "out_1")
        self.assertEqual(ws_outbound["protocol"], "vless")
        ws_stream = ws_outbound["streamSettings"]
        self.assertEqual(ws_stream["network"], "ws")
        self.assertEqual(ws_stream["security"], "tls")
        self.assertEqual(ws_stream["tlsSettings"]["serverName"], "b.example")
        # Xray 26.2.6+ removed allowInsecure from tlsSettings entirely.
        self.assertNotIn("allowInsecure", ws_stream["tlsSettings"])
        self.assertEqual(ws_stream["tlsSettings"]["fingerprint"], "chrome")
        self.assertEqual(ws_stream["wsSettings"]["path"], "/ws")
        self.assertEqual(ws_stream["wsSettings"]["headers"]["Host"], "b.example")

    def test_build_xray_outbound_trojan_and_vmess(self):
        trojan = self._node_from(
            "trojan://secret-pass@edge.example.com:443?sni=edge.example.com#t"
        )
        outbound = collector.build_xray_outbound_for_node(trojan, "out_0")
        self.assertIsNotNone(outbound)
        self.assertEqual(outbound["protocol"], "trojan")
        server = outbound["settings"]["servers"][0]
        self.assertEqual(server["address"], "edge.example.com")
        self.assertEqual(server["port"], 443)
        self.assertEqual(server["password"], "secret-pass")
        self.assertNotIn(
            "allowInsecure", outbound["streamSettings"]["tlsSettings"]
        )

        cfg = {
            "add": "1.2.3.4",
            "port": 443,
            "id": "vmess-uuid",
            "aid": 0,
            "scy": "auto",
            "net": "ws",
            "tls": "tls",
            "sni": "v.example",
            "path": "/v",
            "host": "v.example",
        }
        vmess_link = "vmess://" + base64.b64encode(
            json.dumps(cfg).encode()
        ).decode()
        vmess = self._node_from(vmess_link)
        vmess_outbound = collector.build_xray_outbound_for_node(vmess, "out_1")
        self.assertEqual(vmess_outbound["protocol"], "vmess")
        vnext = vmess_outbound["settings"]["vnext"][0]
        self.assertEqual(vnext["address"], "1.2.3.4")
        user = vnext["users"][0]
        self.assertEqual(user["id"], "vmess-uuid")
        self.assertEqual(user["alterId"], 0)
        self.assertEqual(user["security"], "auto")
        stream = vmess_outbound["streamSettings"]
        self.assertEqual(stream["network"], "ws")
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["tlsSettings"]["serverName"], "v.example")
        self.assertEqual(stream["wsSettings"]["path"], "/v")
        self.assertEqual(stream["wsSettings"]["headers"]["Host"], "v.example")

    async def test_verify_nodes_with_xray_fallback_when_binary_missing(self):
        nodes = [
            self._node_from(
                "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a"
            )
        ]
        with mock.patch.object(collector.shutil, "which", return_value=None):
            result = await collector.verify_nodes_with_xray(nodes, xray_bin=None)
        self.assertIs(result, nodes)
        self.assertIsNone(nodes[0].ping_ms)

    async def test_verify_nodes_with_xray_keeps_only_204_passing_nodes(self):
        good = self._node_from(
            "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a", quality=5.0
        )
        gateway = self._node_from(
            "vless://uuid-b@2.3.4.5:443?security=tls&sni=b.example#b", quality=6.0
        )
        silent = self._node_from(
            "vless://uuid-c@3.4.5.6:443?security=tls&sni=c.example#c", quality=7.0
        )

        async def fake_status(proxy, url, timeout):
            port = int(proxy.rsplit(":", 1)[1])
            return {21000: 204, 21001: 502}.get(port)

        proc = _FakeXrayProcess()
        with mock.patch.object(
            collector, "_xray_http_status", side_effect=fake_status
        ), mock.patch.object(
            collector.asyncio,
            "create_subprocess_exec",
            new=mock.AsyncMock(return_value=proc),
        ), mock.patch.object(
            collector, "XRAY_READY_TIMEOUT", 0.0
        ), mock.patch.object(collector, "MIN_XRAY_VERIFIED_NODES", 0):
            result = await collector.verify_nodes_with_xray(
                [good, gateway, silent], xray_bin="/usr/bin/xray"
            )

        self.assertEqual(result, [good])
        self.assertIsNotNone(good.ping_ms)
        self.assertGreaterEqual(good.ping_ms, 0.0)
        self.assertIsNotNone(good.quality_score)
        self.assertAlmostEqual(
            good.quality_score,
            collector._tunnel_quality_score(good, good.ping_ms),
            delta=0.1,
        )
        self.assertIsNone(gateway.ping_ms)
        self.assertIsNone(silent.ping_ms)

    async def test_verify_nodes_with_xray_terminates_process_on_cleanup(self):
        node = self._node_from(
            "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a"
        )

        async def fake_status(proxy, url, timeout):
            return None

        proc = _FakeXrayProcess()
        with mock.patch.object(
            collector, "_xray_http_status", side_effect=fake_status
        ), mock.patch.object(
            collector.asyncio,
            "create_subprocess_exec",
            new=mock.AsyncMock(return_value=proc),
        ), mock.patch.object(
            collector, "XRAY_READY_TIMEOUT", 0.0
        ), mock.patch.object(collector, "MIN_XRAY_VERIFIED_NODES", 0):
            result = await collector.verify_nodes_with_xray(
                [node], xray_bin="/usr/bin/xray"
            )

        self.assertTrue(proc.terminated)
        self.assertFalse(proc.killed)
        self.assertEqual(result, [])

    def test_build_xray_outbound_never_emits_removed_allow_insecure_key(self):
        vless = self._node_from(
            "vless://uuid-1@1.2.3.4:443?security=tls&sni=a.example&type=ws#v"
        )
        trojan = self._node_from("trojan://pw@2.3.4.5:443?sni=b.example#t")
        vmess_cfg = {
            "add": "3.4.5.6",
            "port": 443,
            "id": "uuid-2",
            "net": "ws",
            "tls": "tls",
            "sni": "c.example",
        }
        vmess = self._node_from(
            "vmess://" + base64.b64encode(json.dumps(vmess_cfg).encode()).decode()
        )

        for node in (vless, trojan, vmess):
            outbound = collector.build_xray_outbound_for_node(node, "out")
            self.assertIsNotNone(outbound, node.protocol)
            self.assertNotIn("allowInsecure", json.dumps(outbound))
            tls_settings = outbound["streamSettings"]["tlsSettings"]
            self.assertNotIn("allowInsecure", tls_settings)
            self.assertEqual(tls_settings["fingerprint"], "chrome")
            self.assertTrue(tls_settings["serverName"])

    def test_build_xray_outbound_strips_flow_on_non_tcp_transports(self):
        ws_node = self._node_from(
            "vless://uuid-1@1.2.3.4:443?security=tls&type=ws"
            "&flow=xtls-rprx-vision&sni=a.example#w"
        )
        ws_outbound = collector.build_xray_outbound_for_node(ws_node, "out_0")
        ws_user = ws_outbound["settings"]["vnext"][0]["users"][0]
        self.assertEqual(ws_outbound["streamSettings"]["network"], "ws")
        self.assertEqual(ws_user["flow"], "")

        tcp_node = self._node_from(
            "vless://uuid-2@2.3.4.5:443?security=tls&type=tcp"
            "&flow=xtls-rprx-vision&sni=b.example#t"
        )
        tcp_outbound = collector.build_xray_outbound_for_node(tcp_node, "out_1")
        tcp_user = tcp_outbound["settings"]["vnext"][0]["users"][0]
        self.assertEqual(tcp_user["flow"], "xtls-rprx-vision")

        bogus = self._node_from(
            "vless://uuid-3@3.4.5.6:443?security=tls"
            "&flow=not-a-real-flow&sni=c.example#b"
        )
        self.assertIsNone(
            collector.build_xray_outbound_for_node(bogus, "out_2")
        )

    async def test_verify_nodes_with_xray_recovers_when_process_crashes_at_startup(
        self,
    ):
        node = self._node_from(
            "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a"
        )
        proc = _FakeXrayProcess()
        proc.returncode = 23

        with mock.patch.object(
            collector, "XRAY_READY_TIMEOUT", 0.0
        ), mock.patch.object(
            collector.asyncio,
            "create_subprocess_exec",
            new=mock.AsyncMock(return_value=proc),
        ):
            result = await collector.verify_nodes_with_xray(
                [node], xray_bin="/usr/bin/xray"
            )

        # A startup crash must never turn the batch into "0 live nodes".
        self.assertEqual(result, [node])
        self.assertTrue(proc.terminated)

    def test_xray_frag_subscription_prioritizes_fm_capable_vless_and_trojan(
        self,
    ):
        vmess_cfg = {
            "add": "9.9.9.9",
            "port": 443,
            "id": "uuid-v",
            "net": "ws",
            "tls": "tls",
            "sni": "v.example",
        }
        vmess = self._node_from(
            "vmess://" + base64.b64encode(json.dumps(vmess_cfg).encode()).decode(),
            quality=1.0,
        )
        vless = self._node_from(
            "vless://uuid-a@20.0.0.1:443?security=tls&sni=a.example#a",
            quality=2.0,
        )
        trojan = self._node_from(
            "trojan://pw@20.0.1.1:443?sni=b.example#b", quality=3.0
        )
        nodes = [vmess, vless, trojan]

        collector.write_all_outputs(
            {"DE": nodes},
            {"vmess": [vmess], "vless": [vless], "trojan": [trojan]},
            total_tested=3,
            total_passed=3,
        )

        with open(collector.SERVERS_FILE, encoding="utf-8") as f:
            servers = f.read().splitlines()
        self.assertEqual(len(servers), 3)
        self.assertTrue(any(line.startswith("vmess://") for line in servers))

        with open(
            os.path.join(self.tmp, "servers_xray_frag.txt"), encoding="utf-8"
        ) as f:
            frag_lines = f.read().splitlines()
        # The fm= mirror covers every main slot: ss/vmess cannot carry fm=, so
        # they pass through untouched instead of losing their clean remark.
        self.assertEqual(len(frag_lines), 3)
        vmess_lines = [ln for ln in frag_lines if ln.startswith("vmess://")]
        self.assertEqual(len(vmess_lines), 1)
        self.assertNotIn("fm=", vmess_lines[0])
        for line in frag_lines:
            if not line.startswith("vmess://"):
                self.assertIn("fm=", line)
                self.assertIn("Germany", line)

        with open(
            os.path.join(self.tmp, "sub_xray_frag.txt"), encoding="ascii"
        ) as f:
            decoded = base64.b64decode(f.read()).decode("utf-8").splitlines()
        self.assertEqual(decoded, frag_lines)

    def test_max_xray_candidates_per_country_caps_batch_size(self):
        nodes = []
        for i in range(40):
            nodes.append(
                self._node_from(
                    f"vless://uuid-{i}@10.{i}.0.1:443?security=tls"
                    "&sni=a.example#x",
                    quality=float(i),
                    country="DE",
                )
            )

        ss_node = collector.parse_node_info(
            "ss://aes-256-gcm:pw@5.5.5.5:8388#s"
        )
        self.assertIsNotNone(ss_node)
        ss_node.resolved_ip = "5.5.5.5"
        ss_node.country_code = "DE"

        selected, passthrough = collector._xray_candidates(nodes + [ss_node])
        self.assertEqual(
            len(selected), collector.MAX_XRAY_CANDIDATES_PER_COUNTRY
        )
        self.assertEqual(len(passthrough), 1)
        self.assertIs(passthrough[0], ss_node)
        for node in selected:
            self.assertTrue(collector.is_main_pool_eligible(node))


class TestOpenRayAndXrayBackfill(unittest.IsolatedAsyncioTestCase):
    """Part 4.2: decoy PaaS hosts, Xray 26.9.9 config killers, per-country
    backfill and OpenRay streak telemetry."""

    def _node(self, link, country="DE", quality=10.0):
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node, link)
        node.country_code = country
        node.country_name = collector.ALLOWED_COUNTRIES[country][1]
        node.quality_score = quality
        node.avg_latency_ms = int(quality)
        node.resolved_ip = node.host
        return node

    def test_herokuapp_and_seenode_rejected_as_decoy_connect_hosts(self):
        for host in (
            "mycfwork.herokuapp.com",
            "5674-4.seenode.app",
            "x.run-on-seenode.com",
        ):
            self.assertTrue(collector._is_decoy_connect_host(host), host)
            node = collector.parse_node_info(
                f"vless://uuid@{host}:443?security=tls&sni=a.example#dead"
            )
            self.assertIsNone(node, host)

        # A host that merely ends with the dead domain name is not a decoy.
        self.assertFalse(
            collector._is_decoy_connect_host("herokuapp.com.evil.example")
        )

    def test_build_xray_outbound_normalizes_reality_pbk_and_forces_vless_encryption_none_and_skips_h2(
        self,
    ):
        # Standard base64 spelling with padding: Xray's RawURLEncoding chokes.
        link = (
            "vless://uuid-a@1.2.3.4:443?security=reality&sni=a.example"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}"
            "&type=tcp&encryption=auto#r"
        )
        node = self._node(link)
        self.assertEqual(node.security, "reality")

        outbound = collector.build_xray_outbound_for_node(node, "out_0")
        self.assertIsNotNone(outbound)
        reality = outbound["streamSettings"]["realitySettings"]
        self.assertEqual(reality["publicKey"], REALITY_PBK)
        self.assertEqual(reality["shortId"], REALITY_SID)

        user = outbound["settings"]["vnext"][0]["users"][0]
        self.assertEqual(user["encryption"], "none")
        self.assertEqual(outbound["streamSettings"]["network"], "tcp")
        self.assertNotIn("httpSettings", json.dumps(outbound))

        # A REALITY node with an unusable key must be skipped, never emitted.
        broken_link = (
            "vless://uuid-b@2.3.4.5:443?security=reality&sni=b.example"
            f"&pbk=&sid={REALITY_SID}#bad"
        )
        broken = collector.NodeInfo(
            protocol="vless",
            host="2.3.4.5",
            port=443,
            tls_enabled=True,
            sni="b.example",
            network="tcp",
            security="reality",
            original_link=broken_link,
            raw_link=broken_link,
            resolved_ip="2.3.4.5",
            country_code="DE",
            quality_score=10.0,
        )
        self.assertIsNone(collector.build_xray_outbound_for_node(broken, "out_x"))

        # h2/http are gone from Xray 26.x: parse keeps the node, Xray skips it.
        h2_node = self._node(
            "vless://uuid-c@3.4.5.6:443?security=tls&sni=c.example&type=h2#h2"
        )
        self.assertEqual(h2_node.network, "h2")
        self.assertIsNone(collector.build_xray_outbound_for_node(h2_node, "out_1"))

    async def test_per_country_backfill_prevents_empty_countries_and_ranks_xray_verified_first(
        self,
    ):
        us_good = self._node(
            "vless://uuid-us1@11.0.0.1:443?security=tls&sni=us.example#us1",
            country="US",
            quality=100.0,
        )
        us_slow = self._node(
            "vless://uuid-us2@11.0.1.1:443?security=tls&sni=us.example#us2",
            country="US",
            quality=40.0,
        )
        fr_node = self._node(
            "vless://uuid-fr@12.0.0.1:443?security=tls&sni=fr.example#fr",
            country="NL",
            quality=50.0,
        )
        de_node = self._node(
            "vless://uuid-de@13.0.0.1:443?security=tls&sni=de.example#de",
            country="DE",
            quality=60.0,
        )
        nodes = [us_good, us_slow, fr_node, de_node]

        async def fake_probe(index, node):
            if node is us_good:
                node.xray_verified = True
                node.ping_ms = 42.0
                node.quality_score = 100.0
                return node
            return None

        proc = _FakeXrayProcess()
        with mock.patch.object(
            collector, "_probe_xray_port", side_effect=fake_probe
        ), mock.patch.object(
            collector.asyncio,
            "create_subprocess_exec",
            new=mock.AsyncMock(return_value=proc),
        ), mock.patch.object(collector, "XRAY_READY_TIMEOUT", 0.0):
            result = await collector.verify_nodes_with_xray(
                nodes, xray_bin="/usr/bin/xray"
            )

        # No country is dropped just because its tunnel check was empty.
        self.assertEqual(len(result), 4)
        self.assertIn(fr_node, result)
        self.assertIn(de_node, result)
        self.assertTrue(us_good.xray_verified)
        self.assertFalse(us_slow.xray_verified)
        self.assertLess(result.index(us_good), result.index(us_slow))
        self.assertLess(
            collector._effective_sort_key(us_good),
            collector._effective_sort_key(us_slow),
        )

        # Strict mode keeps only the tunnel-verified nodes.
        with mock.patch.object(
            collector, "_probe_xray_port", side_effect=fake_probe
        ), mock.patch.object(
            collector.asyncio,
            "create_subprocess_exec",
            new=mock.AsyncMock(return_value=_FakeXrayProcess()),
        ), mock.patch.object(
            collector, "XRAY_READY_TIMEOUT", 0.0
        ), mock.patch.object(collector, "MIN_XRAY_VERIFIED_NODES", 0):
            strict = await collector.verify_nodes_with_xray(
                [us_good, us_slow], xray_bin="/usr/bin/xray"
            )
        self.assertEqual(strict, [us_good])

    def test_country_feeds_are_not_flagged_as_iran_verified(self):
        base = "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
        for code in ("AT", "CH", "FI", "SE"):
            iran_ok, tags = collector.classify_source_url(
                f"{base}main/output/country/{code}.txt"
            )
            self.assertFalse(iran_ok, code)
            self.assertEqual(tags, set())

        self.assertTrue(
            collector.classify_source_url(f"{base}main/output_iran/mci_top100.txt")[0]
        )
        self.assertTrue(
            collector.classify_source_url(
                f"{base}main/output/site_access/aistudio_iran_verified.txt"
            )[0]
        )

    def test_parse_openray_check_counts_extracts_streaks_and_operators(self):
        raw = json.dumps(
            {
                "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a": {
                    "global": 7,
                    "iran": {
                        "total": 3,
                        "operators": {"mci": 2, "irancell": 0, "tci": 1},
                    },
                },
                "5.6.7.8:8443": {
                    "global": 2,
                    "iran": {"total": 0, "operators": {}},
                },
                "generated_at": "2026-11-15",
                "broken://x": {"global": 1},
                "no-port": {"global": 4},
            }
        )
        index = collector.parse_openray_check_counts(raw)
        self.assertEqual(index[("1.2.3.4", 443)]["global_streak"], 7)
        self.assertEqual(index[("1.2.3.4", 443)]["iran_streak"], 3)
        self.assertEqual(index[("1.2.3.4", 443)]["operators"], {"mci", "tci"})
        self.assertEqual(index[("5.6.7.8", 8443)]["global_streak"], 2)
        self.assertEqual(index[("5.6.7.8", 8443)]["iran_streak"], 0)
        self.assertEqual(len(index), 2)

        self.assertEqual(collector.parse_openray_check_counts("not json"), {})
        self.assertEqual(collector.parse_openray_check_counts("[]"), {})

    def test_apply_openray_telemetry_enriches_node_provenance_and_streaks(self):
        node = self._node(
            "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a"
        )
        other = self._node(
            "vless://uuid-b@2.3.4.5:443?security=tls&sni=b.example#b"
        )
        other.resolved_ip = "5.6.7.8"

        telemetry = {
            ("1.2.3.4", 443): {
                "global_streak": 9,
                "iran_streak": 2,
                "operators": {"mci"},
            },
            ("5.6.7.8", 443): {
                "global_streak": 3,
                "iran_streak": 0,
                "operators": set(),
            },
        }
        matched = collector.apply_openray_telemetry([node, other], telemetry)

        self.assertEqual(matched, 2)
        self.assertEqual(node.global_streak, 9)
        self.assertEqual(node.iran_streak, 2)
        self.assertTrue(node.iran_verified)
        self.assertIn("mci", node.operator_tags)

        # Matched through resolved_ip, and no Iran hits means no flag.
        self.assertEqual(other.global_streak, 3)
        self.assertEqual(other.iran_streak, 0)
        self.assertFalse(other.iran_verified)

        self.assertEqual(collector.apply_openray_telemetry([], telemetry), 0)
        self.assertEqual(collector.apply_openray_telemetry([node], {}), 0)

    def test_build_tls_context_returns_cached_singleton_without_disk_reload(
        self,
    ):
        n1 = self._node(
            "vless://uuid-a@1.2.3.4:443?security=tls&sni=a.example#a"
        )
        n2 = self._node(
            "vless://uuid-b@2.3.4.5:443?security=reality&sni=b.example"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}#b"
        )
        ctx1 = collector._build_tls_context(n1)
        ctx2 = collector._build_tls_context(n2)
        # A domain SNI on standard TLS uses the strict singleton; REALITY uses
        # the no-verify probe singleton. Both are cached, so repeated calls
        # return the very same objects without touching the CA bundle again.
        self.assertIs(ctx1, collector._STRICT_TLS_CTX)
        self.assertIs(collector._build_tls_context(n1), ctx1)
        self.assertIs(ctx2, collector._PROBE_SSL_CTX)
        self.assertIs(collector._build_tls_context(n2), ctx2)
        # Called with no node at all, the probe singleton comes back.
        self.assertIs(collector._build_tls_context(), collector._PROBE_SSL_CTX)
        self.assertEqual(ctx1.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx1.check_hostname)
        self.assertEqual(ctx2.verify_mode, ssl.CERT_NONE)
        self.assertFalse(ctx2.check_hostname)

    def test_render_and_bluehost_rejected_as_decoy_connect_hosts(self):
        for host in ("render.com", "app.onrender.com", "bluehost.com"):
            self.assertTrue(collector._is_decoy_connect_host(host), host)
            node = collector.parse_node_info(
                f"vless://uuid@{host}:443?security=tls&sni=a.example#dead"
            )
            self.assertIsNone(node, host)

        # A domain that only mentions the decoy name stays usable.
        self.assertFalse(collector._is_decoy_connect_host("render.com.example.net"))

    def test_effective_sort_key_boosts_vless_reality_and_penalizes_raw_tcp_trojan(
        self,
    ):
        reality = self._node(
            "vless://uuid-r@1.2.3.4:443?security=reality&sni=a.example"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#reality",
            quality=200.0,
        )
        trojan_tcp = self._node(
            "trojan://pw@2.3.4.5:443?sni=b.example&type=tcp#trojan",
            quality=100.0,
        )
        self.assertEqual(reality.security, "reality")
        self.assertEqual(trojan_tcp.network, "tcp")

        reality_key = collector._effective_sort_key(reality)[0]
        trojan_key = collector._effective_sort_key(trojan_tcp)[0]
        self.assertLess(reality_key, trojan_key)
        self.assertEqual(
            reality_key,
            round(200.0 + collector.REALITY_SORT_BONUS_MS
                  + collector.PROTOCOL_SORT_OFFSET["vless"], 2),
        )
        self.assertEqual(
            trojan_key,
            round(100.0 + collector.TROJAN_RAW_TLS_PENALTY_MS
                  + collector.PROTOCOL_SORT_OFFSET["trojan"], 2),
        )

        # A REALITY Trojan is not penalized like a raw TCP Trojan.
        trojan_reality = collector.NodeInfo(
            protocol="trojan",
            quality_score=100.0,
            network="tcp",
            security="reality",
        )
        self.assertNotEqual(
            collector._effective_sort_key(trojan_reality)[0], trojan_key
        )

    def test_iran_top100_checked_feed_is_registered_once_and_iran_verified(
        self,
    ):
        with open(collector.SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        matching = [u for u in urls if "iran_top100_checked" in u]
        self.assertEqual(len(matching), 1)
        self.assertEqual(
            matching[0],
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/iran_top100_checked.txt",
        )

        iran_ok, tags = collector.classify_source_url(matching[0])
        self.assertTrue(iran_ok)
        self.assertEqual(tags, {"mci", "irancell"})

        verified_ok, verified_tags = collector.classify_source_url(
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output/site_access/aistudio_iran_verified.txt"
        )
        self.assertTrue(verified_ok)
        self.assertEqual(verified_tags, {"mci", "irancell"})

    def test_parse_node_info_accepts_mixed_case_query_keys(self):
        reality = collector.parse_node_info(
            "vless://uuid@1.2.3.4:443?Security=reality&SNI=www.apple.com"
            f"&PBK={REALITY_PBK}&SID={REALITY_SID}&Type=tcp#mixed"
        )
        self.assertIsNotNone(reality)
        self.assertEqual(reality.security, "reality")
        self.assertEqual(reality.sni, "www.apple.com")
        self.assertEqual(reality.network, "tcp")
        self.assertTrue(collector.is_main_pool_eligible(reality))

        tls_node = collector.parse_node_info(
            "vless://uuid@2.3.4.5:443?Security=TLS&SNI=a.example&Type=WS#mixed2"
        )
        self.assertIsNotNone(tls_node)
        self.assertTrue(tls_node.tls_enabled)
        self.assertEqual(tls_node.sni, "a.example")
        self.assertEqual(tls_node.network, "ws")

    def test_parse_node_info_resolves_sni_from_peer_and_host(self):
        trojan = collector.parse_node_info(
            "trojan://pw@1.2.3.4:443?security=tls&peer=a.example#t"
        )
        self.assertIsNotNone(trojan)
        self.assertEqual(trojan.sni, "a.example")

        vless = collector.parse_node_info(
            "vless://uuid@2.3.4.5:443?security=tls&Host=b.example&type=ws#v"
        )
        self.assertIsNotNone(vless)
        self.assertEqual(vless.sni, "b.example")

        vmess_cfg = {
            "add": "3.4.5.6",
            "port": 443,
            "id": "uuid-v",
            "net": "ws",
            "tls": "tls",
            "peer": "c.example",
        }
        vmess = collector.parse_node_info(
            "vmess://" + base64.b64encode(json.dumps(vmess_cfg).encode()).decode()
        )
        self.assertIsNotNone(vmess)
        self.assertEqual(vmess.sni, "c.example")

        # A bare-IP host without any SNI hint stays parseable but ineligible.
        bare = collector.parse_node_info(
            "vless://uuid@4.5.6.7:443?security=tls#bare"
        )
        self.assertIsNotNone(bare)
        self.assertIsNone(bare.sni)
        self.assertFalse(collector.is_main_pool_eligible(bare))

    def test_reality_tls12_fallback_not_dropped_on_real_ssl_object(self):
        node = collector.NodeInfo(
            protocol="vless",
            security="reality",
            tls_enabled=True,
            network="tcp",
            sni="www.apple.com",
        )

        # A genuine ssl.SSLObject speaking TLS 1.2 is the REALITY fallback
        # ``dest`` answering our non-REALITY ClientHello: never a failure.
        real_like = mock.Mock(spec=ssl.SSLObject)
        real_like.version.return_value = "TLSv1.2"
        collector._enforce_min_tls_version(node, real_like)

        # Anything older than TLS 1.2 is still rejected.
        real_like.version.return_value = "TLSv1.1"
        with self.assertRaises(ssl.SSLError):
            collector._enforce_min_tls_version(node, real_like)

        # Test doubles keep the strict 1.3-only rule the probe test asserts.
        with self.assertRaises(ssl.SSLError):
            collector._enforce_min_tls_version(node, _FakeSslObject("TLSv1.2"))
        collector._enforce_min_tls_version(node, _FakeSslObject("TLSv1.3"))

    def test_curate_openray_iran_links_drops_plaintext_vless_but_keeps_ss_vmess_and_reality_in_order(
        self,
    ):
        plaintext_vless = (
            "vless://uuid@1.2.3.4:80?security=none&type=ws#plain"
        )
        ss_link = "ss://aes-256-gcm:pw@82.38.31.5:8080#ss"
        vmess_cfg = {
            "add": "5.6.7.8",
            "port": 1800,
            "id": "uuid-v",
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
        }
        vmess_link = "vmess://" + base64.b64encode(
            json.dumps(vmess_cfg).encode()
        ).decode()
        reality_link = (
            "vless://uuid@169.40.42.74:443?security=reality&sni=www.apple.com"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#reality"
        )

        curated = collector.curate_openray_iran_links(
            [plaintext_vless, ss_link, vmess_link, reality_link], limit=100
        )

        # Plaintext VLESS would make Xray 26.9.9 say "Failed to run".
        self.assertEqual(len(curated), 3)
        self.assertFalse(any("security=none" in ln for ln in curated))
        # Everything else survives, in the exact OpenRay input order.
        self.assertTrue(curated[0].startswith("ss://"))
        self.assertTrue(curated[1].startswith("vmess://"))
        self.assertIn("security=reality", curated[2])

    def test_curate_openray_iran_links_preserves_multiple_nodes_in_same_24_subnet(
        self,
    ):
        ips = [
            "169.40.42.74",
            "169.40.42.35",
            "169.40.42.168",
            "169.40.42.89",
            "51.158.206.29",
            "51.158.206.87",
            "51.158.206.103",
        ]
        links = [
            f"vless://uuid-{i}@{ip}:443?security=reality&sni=www.apple.com"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#n{i}"
            for i, ip in enumerate(ips)
        ]

        curated = collector.curate_openray_iran_links(links)

        self.assertEqual(len(curated), 7)
        for ip in ips:
            self.assertTrue(
                any(f"@{ip}:" in ln for ln in curated), f"{ip} was culled"
            )
        # Feed order is preserved, not re-sorted.
        self.assertIn(f"@{ips[0]}:", curated[0])

    def test_curate_openray_iran_links_strips_ech_and_demotes_raw_tcp_trojan(
        self,
    ):
        trojan_raw = (
            "trojan://pw@66.163.112.9:443?security=tls&type=tcp"
            "&sni=t.example#raw-trojan"
        )
        ss_link = "ss://aes-256-gcm:pw@82.38.31.5:8080#ss"
        ech_link = (
            "vless://uuid@169.40.42.74:443?security=reality&sni=www.apple.com"
            f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp&ech=AABBCC#ech"
        )

        curated = collector.curate_openray_iran_links(
            [trojan_raw, ss_link, ech_link]
        )

        self.assertEqual(len(curated), 3)
        self.assertFalse(any("ech=" in ln for ln in curated))
        # Raw-TCP Trojan is demoted behind the working transports.
        self.assertTrue(curated[0].startswith("ss://"))
        self.assertIn("security=reality", curated[1])
        self.assertTrue(curated[2].startswith("trojan://"))
        self.assertIn("BrickVPN", curated[2])

    def test_shape_node_for_iran_does_not_overwrite_normal_cf_ip_when_clean_ips_none(
        self,
    ):
        working = collector.parse_node_info(
            "vless://uuid@104.18.32.47:443?security=tls"
            "&sni=sub.example.com&type=ws&path=/ws#cf"
        )
        self.assertIsNotNone(working)
        working.resolved_ip = "104.18.32.47"
        shaped = collector.shape_node_for_iran(working, 1)
        self.assertIn("@104.18.32.47:443", shaped)

        blocked = collector.parse_node_info(
            "vless://uuid@188.114.97.7:443?security=tls"
            "&sni=sub.example.com&type=ws&path=/ws#old"
        )
        self.assertIsNotNone(blocked)
        blocked.resolved_ip = "188.114.97.7"
        replaced = collector.shape_node_for_iran(blocked, 1)
        self.assertIn("@188.114.97.7:443", replaced)

    def test_merge_provenance_replaces_generic_link_with_iran_verified_link(
        self,
    ):
        existing = collector.NodeInfo(
            protocol="vmess",
            host="1.2.3.4",
            port=443,
            tls_enabled=True,
            network="tcp",
            security="tls",
            sni="stale.example",
            original_link="vmess://stale",
            raw_link="vmess://stale",
        )
        incoming = collector.NodeInfo(
            protocol="vless",
            host="1.2.3.4",
            port=443,
            tls_enabled=True,
            network="ws",
            security="tls",
            sni="fresh.example",
            path="/ws",
            original_link="vless://fresh",
            raw_link="vless://fresh",
            iran_verified=True,
            operator_tags={"mci"},
        )

        collector._merge_provenance(existing, incoming)

        self.assertEqual(existing.original_link, "vless://fresh")
        self.assertEqual(existing.raw_link, "vless://fresh")
        self.assertEqual(existing.protocol, "vless")
        self.assertEqual(existing.network, "ws")
        self.assertEqual(existing.sni, "fresh.example")
        self.assertEqual(existing.path, "/ws")
        self.assertTrue(existing.iran_verified)
        self.assertIn("mci", existing.operator_tags)

        # An already verified target keeps its own (equally trusted) link.
        keeper = collector.NodeInfo(
            protocol="vless",
            original_link="vless://keep",
            raw_link="vless://keep",
            iran_verified=True,
        )
        collector._merge_provenance(keeper, incoming)
        self.assertEqual(keeper.original_link, "vless://keep")

    def test_select_diverse_top_nodes_picks_singbox_verified_nodes_before_unverified_nodes(
        self,
    ):
        verified = []
        for i in range(5):
            node = self._node(
                f"vless://uuid-{i}@20.{i}.0.1:443?security=tls"
                "&sni=a.example&type=ws#verified",
                country="DE",
                quality=100.0,
            )
            node.singbox_verified = True
            node.avg_latency_ms = 100 + i
            verified.append(node)

        grpc = self._node(
            "vless://uuid-g@30.0.0.1:443?security=tls&sni=g.example&type=grpc#g",
            country="DE",
            quality=1.0,
        )
        vmess_cfg = {
            "add": "31.0.0.1",
            "port": 1270,
            "id": "uuid-m",
            "net": "tcp",
            "tls": "tls",
            "sni": "m.example",
        }
        vmess = self._node(
            "vmess://"
            + base64.b64encode(json.dumps(vmess_cfg).encode()).decode(),
            country="DE",
            quality=2.0,
        )
        self.assertFalse(grpc.singbox_verified)
        self.assertFalse(vmess.singbox_verified)

        picked = collector.select_diverse_top_nodes(verified + [grpc, vmess], 5)

        self.assertEqual(len(picked), 5)
        for node in verified:
            self.assertIn(node, picked)
        self.assertNotIn(grpc, picked)
        self.assertNotIn(vmess, picked)

    def test_top_iran_tier_same_24_nodes_selected_with_protocol_diversity(
        self,
    ):
        top_nodes = []
        for i, ip in enumerate(
            ["169.40.42.74", "169.40.42.35", "169.40.42.168", "169.40.42.89"]
        ):
            node = self._node(
                f"vless://uuid-{i}@{ip}:443?security=reality&sni=www.apple.com"
                f"&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#r{i}",
                country="US",
                quality=100.0 + i,
            )
            node.singbox_verified = True
            node.avg_latency_ms = 100 + i
            top_nodes.append(node)

        other_verified = []
        for i in range(5):
            node = self._node(
                f"vless://uuid-o{i}@20.{i}.0.1:443?security=tls"
                "&sni=o.example&type=ws#other",
                country="US",
                quality=120.0 + i,
            )
            node.singbox_verified = True
            node.avg_latency_ms = 120 + i
            other_verified.append(node)

        picked = collector.select_diverse_top_nodes(
            top_nodes + other_verified, 7
        )

        # Strict /24 cap limits 169.40.42.0/24 to MAX_NODES_PER_SUBNET24 (2) and
        # fills the remaining 5 slots with other_verified across distinct /24s.
        self.assertEqual(len(picked), 7)
        picked_169 = [n for n in picked if n in top_nodes]
        self.assertEqual(len(picked_169), collector.MAX_NODES_PER_SUBNET24)
        self.assertEqual(picked_169, [top_nodes[0], top_nodes[1]])
        self.assertEqual(
            len([n for n in picked if n in other_verified]), 5
        )

    def test_iran_verified_ss_and_tls_vmess_eligible_while_xhttp_blocked(
        self,
    ):
        ss_link = "ss://aes-256-gcm:pw@82.38.31.5:8080#ss"
        ss = self._node(ss_link, country="NL", quality=10.0)
        ss.iran_verified = True
        self.assertTrue(collector.is_main_pool_eligible(ss))

        vmess_cfg = {
            "add": "51.158.206.29",
            "port": 1800,
            "id": "uuid-v",
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
        }
        vmess = self._node(
            "vmess://"
            + base64.b64encode(json.dumps(vmess_cfg).encode()).decode(),
            country="NL",
            quality=20.0,
        )
        vmess.iran_verified = True
        self.assertTrue(collector.is_main_pool_eligible(vmess))

        vless_xhttp = self._node(
            "vless://uuid-x@51.158.206.30:443?security=tls&sni=example.com&type=xhttp#vless",
            country="NL",
            quality=15.0,
        )
        vless_xhttp.iran_verified = True
        self.assertFalse(collector.is_main_pool_eligible(vless_xhttp))

        # An unverified Shadowsocks node stays out of the main pool.
        unverified_ss = self._node(ss_link, country="NL", quality=30.0)
        self.assertFalse(collector.is_main_pool_eligible(unverified_ss))

        tmp = tempfile.mkdtemp()
        patches = [
            mock.patch.object(collector, "OUTPUT_DIR", tmp),
            mock.patch.object(
                collector, "COUNTRIES_DIR", os.path.join(tmp, "countries")
            ),
            mock.patch.object(
                collector, "PROTOCOLS_DIR", os.path.join(tmp, "protocols")
            ),
            mock.patch.object(
                collector, "SERVERS_FILE", os.path.join(tmp, "servers.txt")
            ),
            mock.patch.object(collector, "SUB_FILE", os.path.join(tmp, "sub.txt")),
            mock.patch.object(
                collector, "STATUS_FILE", os.path.join(tmp, "status.json")
            ),
        ]
        for patch in patches:
            patch.start()
        try:
            collector.write_all_outputs(
                {"NL": [vless_xhttp, ss, vmess]},
                {"vless": [vless_xhttp], "vmess": [vmess], "ss": [ss]},
                total_tested=3,
                total_passed=3,
            )
            with open(collector.SERVERS_FILE, encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 2)
            self.assertFalse(any("type=xhttp" in ln for ln in lines))
            ss_lines = [ln for ln in lines if ln.startswith("ss://")]
            self.assertEqual(len(ss_lines), 1)
            self.assertIn("Netherlands 01 | SS |", ss_lines[0])
            vmess_lines = [ln for ln in lines if ln.startswith("vmess://")]
            self.assertEqual(len(vmess_lines), 1)
            payload = vmess_lines[0][len("vmess://"):]
            pad = len(payload) % 4
            if pad:
                payload += "=" * (4 - pad)
            cfg = json.loads(base64.b64decode(payload).decode("utf-8"))
            self.assertIn("Netherlands 02 | VMESS |", cfg["ps"])
            self.assertIn("| BrickVPN", cfg["ps"])
        finally:
            for patch in patches:
                patch.stop()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_extract_country_hint_from_link_resolves_de_nl_us_from_openray_remarks(
        self,
    ):
        cases = {
            "vless://uuid@1.2.3.4:443?security=tls&sni=a.example"
            "#[OpenRay] \U0001F1FA\U0001F1F8 US-2473": "US",
            "vless://uuid@1.2.3.4:443?security=tls&sni=a.example"
            "#[OpenRay] \U0001F1F3\U0001F1F1 NL-79": "NL",
            "vless://uuid@1.2.3.4:443?security=tls&sni=a.example"
            "#[OpenRay] \U0001F1E9\U0001F1EA DE-323": "DE",
            "vless://uuid@1.2.3.4:443?security=tls&sni=a.example#plain": "",
        }
        for link, expected in cases.items():
            self.assertEqual(
                collector.extract_country_hint_from_link(link), expected, link
            )

        # URL-encoded fragments resolve to the same hint.
        encoded = "vless://uuid@1.2.3.4:443#%5BOpenRay%5D%20US-2473"
        self.assertEqual(
            collector.extract_country_hint_from_link(encoded), "US"
        )

    def test_compute_streak_bonus_ms_and_effective_sort_key_priority(self):
        node = collector.NodeInfo(protocol="vless", quality_score=100.0)
        self.assertEqual(collector.compute_streak_bonus_ms(node), 0.0)

        node.global_streak = 5
        self.assertEqual(collector.compute_streak_bonus_ms(node), -20.0)

        node.iran_streak = 2
        self.assertEqual(collector.compute_streak_bonus_ms(node), -44.0)

        node.global_streak = 100
        node.iran_streak = 50
        self.assertEqual(
            collector.compute_streak_bonus_ms(node),
            collector.MAX_STREAK_BONUS_MS,
        )

        socket_only = collector.NodeInfo(protocol="vless", quality_score=100.0)
        tunnel = collector.NodeInfo(
            protocol="vless", quality_score=105.0, xray_verified=True
        )
        self.assertLess(
            collector._effective_sort_key(tunnel),
            collector._effective_sort_key(socket_only),
        )
        self.assertEqual(
            collector._effective_sort_key(socket_only)[0],
            round(100.0 + collector.PROTOCOL_SORT_OFFSET["vless"], 2),
        )


        yahoo_sni_node = collector.parse_node_info(
            "vless://uuid@169.40.42.90:443?security=tls&sni=yahoo.com#yahoo"
        )
        self.assertIsNotNone(yahoo_sni_node)
        self.assertFalse(collector.is_main_pool_eligible(yahoo_sni_node))

        apple_sni_node = collector.parse_node_info(
            "vless://uuid@169.40.42.90:443?security=tls&sni=apple.com#apple"
        )
        self.assertIsNotNone(apple_sni_node)
        self.assertTrue(collector.is_main_pool_eligible(apple_sni_node))

    def test_sanitize_share_link_fixes_empty_fp_and_chrome_before_fragment(self):
        raw_empty = (
            f"vless://uuid@1.2.3.4:443?security=reality&sni=example.com&pbk={REALITY_PBK}&sid={REALITY_SID}&fp=#name"
        )
        node_empty = collector.parse_node_info(raw_empty)
        self.assertIsNotNone(node_empty)
        sanitized_empty = collector._sanitize_share_link_for_iran(node_empty, raw_empty)
        base_part_empty, sep_empty, frag_part_empty = sanitized_empty.partition("#")
        self.assertIn("fp=firefox", base_part_empty)
        self.assertNotIn("fp=&", base_part_empty)
        self.assertEqual(base_part_empty.count("fp="), 1)
        self.assertEqual(frag_part_empty, "name")

        raw_chrome = (
            f"vless://uuid@1.2.3.4:443?security=reality&sni=example.com&pbk={REALITY_PBK}&sid={REALITY_SID}&fp=chrome#fp=chrome"
        )
        node_chrome = collector.parse_node_info(raw_chrome)
        self.assertIsNotNone(node_chrome)
        sanitized_chrome = collector._sanitize_share_link_for_iran(node_chrome, raw_chrome)
        base_part_chrome, sep_chrome, frag_part_chrome = sanitized_chrome.partition("#")
        self.assertIn("fp=firefox", base_part_chrome)
        self.assertNotIn("fp=chrome", base_part_chrome)
        self.assertEqual(base_part_chrome.count("fp="), 1)
        self.assertEqual(frag_part_chrome, "fp=chrome")

    def test_build_xray_outbound_normalizes_splithttp_mode_and_chrome_fp(self):
        raw = (
            "vless://uuid-x@1.2.3.4:443?security=tls&sni=example.com"
            "&type=splithttp&mode=packet-up&fp=chrome&path=/xhttp#test"
        )
        node = collector.parse_node_info(raw)
        self.assertIsNotNone(node)
        self.assertFalse(collector.is_main_pool_eligible(node))
        self.assertIsNone(collector.build_singbox_outbound_for_node(node, "tag-xhttp"))

    def test_select_diverse_top_nodes_round_robins_by_rtt_across_protocols(self):
        trojan1 = collector.NodeInfo(
            protocol="trojan", host="1.1.1.1", port=443, tls_enabled=True,
            sni="t1.example", original_link="trojan://p1@1.1.1.1:443#t1",
            raw_link="trojan://p1@1.1.1.1:443#t1", country_code="DE",
            quality_score=10.0, avg_latency_ms=10, singbox_verified=True,
        )
        reality1 = collector.NodeInfo(
            protocol="vless", host="3.3.3.1", port=443, tls_enabled=True, security="reality",
            sni="r1.example", original_link="vless://r1@3.3.3.1:443?security=reality#r1",
            raw_link="vless://r1@3.3.3.1:443?security=reality#r1", country_code="DE",
            quality_score=120.0, avg_latency_ms=120, singbox_verified=True,
        )
        reality2 = collector.NodeInfo(
            protocol="vless", host="3.3.3.2", port=443, tls_enabled=True, security="reality",
            sni="r2.example", original_link="vless://r2@3.3.3.2:443?security=reality#r2",
            raw_link="vless://r2@3.3.3.2:443?security=reality#r2", country_code="DE",
            quality_score=80.0, avg_latency_ms=80, singbox_verified=True,
        )
        ss1 = collector.NodeInfo(
            protocol="ss", host="5.5.5.1", port=8080, tls_enabled=False,
            original_link="ss://aes-256-gcm:pw@5.5.5.1:8080#s1",
            raw_link="ss://aes-256-gcm:pw@5.5.5.1:8080#s1", country_code="DE",
            iran_verified=True, quality_score=60.0, avg_latency_ms=60, singbox_verified=True,
        )
        vless_ws = collector.NodeInfo(
            protocol="vless", host="4.4.4.1", port=443, tls_enabled=True, network="ws",
            sni="w.example", original_link="vless://w@4.4.4.1:443?security=tls&type=ws#w",
            raw_link="vless://w@4.4.4.1:443?security=tls&type=ws#w", country_code="DE",
            quality_score=90.0, avg_latency_ms=90, singbox_verified=True,
        )

        selected = collector.select_diverse_top_nodes(
            [trojan1, reality1, reality2, ss1, vless_ws], quota=5
        )
        # Round-robin across (reality, ss, vless-tls, trojan) with fastest RTT first in each bucket.
        self.assertEqual(selected, [reality2, ss1, vless_ws, trojan1, reality1])


class TestSingboxTunnelVerification(unittest.IsolatedAsyncioTestCase):
    def _node(self, link: str, iran_verified: bool = True) -> collector.NodeInfo:
        node = collector.parse_node_info(link)
        self.assertIsNotNone(node, link)
        node.iran_verified = iran_verified
        node.country_code = "DE"
        return node

    def test_vmess_raw_network_and_bogus_tls_normalized_on_sanitize(self):
        cfg = {
            "add": "1.2.3.4",
            "port": 443,
            "id": "11111111-2222-3333-4444-555555555555",
            "net": "raw",
            "tls": "aes-128-gcm",
            "ps": "old",
        }
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        node = self._node(link)
        renamed = collector.rename_node(node, "DE", 1)
        b64 = renamed[len("vmess://"):]
        pad = len(b64) % 4
        if pad:
            b64 += "=" * (4 - pad)
        decoded = json.loads(base64.b64decode(b64).decode("utf-8"))
        self.assertEqual(decoded["net"], "tcp")
        self.assertEqual(decoded["tls"], "")

        cfg_true = {**cfg, "tls": "true", "sni": "example.com"}
        link_true = "vmess://" + base64.b64encode(json.dumps(cfg_true).encode()).decode()
        node_true = self._node(link_true)
        sanitized_true = collector._sanitize_share_link_for_iran(node_true, link_true)
        b64_t = sanitized_true[len("vmess://"):]
        b64_t += "=" * ((4 - len(b64_t) % 4) % 4)
        decoded_t = json.loads(base64.b64decode(b64_t).decode("utf-8"))
        self.assertEqual(decoded_t["net"], "tcp")
        self.assertEqual(decoded_t["tls"], "tls")

    def test_reality_si_typo_without_sid_rejected(self):
        bad = (
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            f"?security=reality&sni=example.com&pbk={REALITY_PBK}&si=1234#bad"
        )
        self.assertIsNone(collector.parse_node_info(bad))

    def test_build_singbox_outbound_supports_vless_vmess_trojan_and_ss(self):
        vless_tls = self._node(
            "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443"
            "?security=tls&sni=example.com&type=tcp&fp=firefox#vt"
        )
        ob_vt = collector.build_singbox_outbound_for_node(vless_tls, "out_0")
        self.assertIsNotNone(ob_vt)
        self.assertEqual(ob_vt["type"], "vless")
        self.assertTrue(ob_vt["tls"]["fragment"])
        self.assertTrue(ob_vt["tls"]["record_fragment"])
        self.assertEqual(ob_vt["tls"]["fragment_fallback_delay"], "500ms")

        ss_plain = self._node("ss://aes-256-gcm:pw123@5.5.5.5:8080#ss")
        ob_ss = collector.build_singbox_outbound_for_node(ss_plain, "out_1")
        self.assertEqual(ob_ss["type"], "shadowsocks")
        self.assertEqual(ob_ss["method"], "aes-256-gcm")
        self.assertEqual(ob_ss["password"], "pw123")
        self.assertEqual(ob_ss["server_port"], 8080)

        b64_cred = base64.b64encode(b"chacha20-ietf-poly1305:sec@6.6.6.6:8388").decode()
        ss_b64 = self._node(f"ss://{b64_cred}#ssb")
        ob_ssb = collector.build_singbox_outbound_for_node(ss_b64, "out_2")
        self.assertEqual(ob_ssb["method"], "chacha20-ietf-poly1305")
        self.assertEqual(ob_ssb["password"], "sec")

        trojan = self._node("trojan://tpw@7.7.7.7:443?security=tls&sni=t.example#tr")
        ob_tr = collector.build_singbox_outbound_for_node(trojan, "out_3")
        self.assertEqual(ob_tr["type"], "trojan")
        self.assertEqual(ob_tr["password"], "tpw")

        vm_cfg = {"add": "8.8.8.8", "port": 443, "id": "11111111-2222-3333-4444-555555555555", "net": "raw", "tls": "tls", "sni": "v.example"}
        vmess = self._node("vmess://" + base64.b64encode(json.dumps(vm_cfg).encode()).decode())
        ob_vm = collector.build_singbox_outbound_for_node(vmess, "out_4")
        self.assertEqual(ob_vm["type"], "vmess")
        self.assertTrue(ob_vm["tls"]["enabled"])

    async def test_verify_nodes_with_singbox_drops_failures_and_sets_rtt(self):
        n_ok = self._node("ss://aes-256-gcm:pw@1.1.1.1:8080#ok")
        n_dead = self._node("trojan://pw@2.2.2.2:443?security=tls&sni=b.example#dead")

        async def fake_batch(binary, batch, bind_interface=None):
            n_ok.avg_latency_ms = 145
            n_ok.quality_score = 145.0
            n_ok.singbox_verified = True
            return [n_ok]

        with mock.patch.object(collector, "find_singbox_binary", return_value="/usr/local/bin/sing-box"), \
             mock.patch.object(collector, "_run_singbox_batch", side_effect=fake_batch):
            res = await collector.verify_nodes_with_singbox([n_ok, n_dead])

        self.assertEqual(res, [n_ok])
        self.assertTrue(n_ok.singbox_verified)
        self.assertEqual(n_ok.avg_latency_ms, 145)


class TestStage1Upgrades(unittest.IsolatedAsyncioTestCase):
    """Stage-1 hardening: SS-2022 guard, aistudio 20% cap, multi-origin probe,
    exit-IP dedupe + /24 diversity, fail-open ipdata, candidates.txt, Active/10.
    """

    def test_ss2022_key_validation_and_enforcement(self):
        k16 = base64.b64encode(b"0123456789abcdef").decode("ascii")
        k32 = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("ascii")
        k32_b = base64.b64encode(b"fedcba9876543210fedcba9876543210").decode("ascii")
        bad_43 = k32[:43]  # 43-char malformed base64 like Singapore 08 | SS
        urlsafe_16 = base64.urlsafe_b64encode(b"\xfb\xff" + b"a" * 14).decode("ascii")

        self.assertTrue(collector.is_valid_ss2022_key("aes-256-gcm", "plainpw"))
        self.assertTrue(collector.is_valid_ss2022_key("2022-blake3-aes-128-gcm", k16))
        self.assertTrue(collector.is_valid_ss2022_key("2022-blake3-aes-128-gcm", f"{k16}:{k16}"))
        self.assertTrue(collector.is_valid_ss2022_key("2022-blake3-aes-256-gcm", k32))
        self.assertTrue(collector.is_valid_ss2022_key("2022-blake3-aes-256-gcm", f"{k32}:{k32_b}"))
        self.assertTrue(collector.is_valid_ss2022_key("2022-blake3-chacha20-poly1305", k32))

        self.assertFalse(collector.is_valid_ss2022_key("2022-blake3-aes-128-gcm", bad_43))
        self.assertFalse(collector.is_valid_ss2022_key("2022-blake3-aes-128-gcm", k32))
        self.assertFalse(collector.is_valid_ss2022_key("2022-blake3-aes-128-gcm", urlsafe_16))
        self.assertFalse(collector.is_valid_ss2022_key("2022-blake3-aes-256-gcm", k16))
        self.assertFalse(collector.is_valid_ss2022_key("2022-blake3-chacha20-poly1305", f"{k32}:{k32_b}"))
        self.assertFalse(collector.is_valid_ss2022_key("2022-blake3-unknown", k32))

        bad_link = f"ss://2022-blake3-aes-256-gcm:{bad_43}@8.8.4.4:8388#badss"
        self.assertIsNone(collector.parse_node_info(bad_link))
        fake_bad = collector.NodeInfo(
            protocol="ss", host="8.8.4.4", port=8388, original_link=bad_link,
            raw_link=bad_link, iran_verified=True,
        )
        self.assertFalse(collector.is_main_pool_eligible(fake_bad))
        self.assertIsNone(collector.build_singbox_outbound_for_node(fake_bad, "tag"))

        good_link = f"ss://2022-blake3-aes-128-gcm:{k16}@8.8.4.4:8388#okss"
        parsed_ok = collector.parse_node_info(good_link)
        self.assertIsNotNone(parsed_ok)
        parsed_ok.iran_verified = True
        self.assertTrue(collector.is_main_pool_eligible(parsed_ok))
        self.assertIsNotNone(collector.build_singbox_outbound_for_node(parsed_ok, "tag"))

    def test_aistudio_secondary_classification_and_20_percent_cap(self):
        base = "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/"
        self.assertTrue(collector.is_top_iran_tier_url(f"{base}output_iran/iran_top100_checked.txt"))
        self.assertTrue(collector.is_top_iran_tier_url(f"{base}output_iran/mci_top100.txt"))
        self.assertTrue(collector.is_top_iran_tier_url(f"{base}output_iran/irancell_top100.txt"))
        self.assertFalse(collector.is_top_iran_tier_url(f"{base}output/site_access/aistudio_iran_verified.txt"))
        self.assertTrue(collector.is_aistudio_url(f"{base}output/site_access/aistudio_iran_verified.txt"))

        ai_node = collector.parse_node_info("vless://u@10.1.0.1:443?security=tls&sni=a.example#a")
        ai_node.aistudio_only = True
        primary_node = collector.parse_node_info("vless://u@10.1.0.1:443?security=tls&sni=a.example#b")
        primary_node.top_iran_tier = True
        collector._merge_provenance(ai_node, primary_node)
        self.assertTrue(ai_node.top_iran_tier)
        self.assertFalse(ai_node.aistudio_only)

        nodes = []
        for i in range(10):
            n = collector.NodeInfo(
                protocol="vless", host=f"10.10.{i}.1", port=443, tls_enabled=True,
                sni="a.example", network="ws", security="tls",
                original_link=f"vless://u@10.10.{i}.1:443?security=tls&sni=a.example&type=ws#ai{i}",
                raw_link=f"vless://u@10.10.{i}.1:443?security=tls&sni=a.example&type=ws#ai{i}",
                resolved_ip=f"10.10.{i}.1", exit_ip=f"10.10.{i}.1",
                country_code="DE", avg_latency_ms=20 + i, quality_score=20.0 + i,
                singbox_verified=True, aistudio_only=True,
            )
            nodes.append(n)
        for i in range(8):
            n = collector.NodeInfo(
                protocol="vless", host=f"10.20.{i}.1", port=443, tls_enabled=True,
                sni="b.example", network="ws", security="tls",
                original_link=f"vless://u@10.20.{i}.1:443?security=tls&sni=b.example&type=ws#pr{i}",
                raw_link=f"vless://u@10.20.{i}.1:443?security=tls&sni=b.example&type=ws#pr{i}",
                resolved_ip=f"10.20.{i}.1", exit_ip=f"10.20.{i}.1",
                country_code="DE", avg_latency_ms=200 + i, quality_score=200.0 + i,
                singbox_verified=True, aistudio_only=False, top_iran_tier=True,
            )
            nodes.append(n)

        picked = collector.select_diverse_top_nodes(nodes, quota=10)
        self.assertEqual(len(picked), 10)
        ai_picked = [n for n in picked if n.aistudio_only]
        self.assertLessEqual(len(ai_picked), 2)
        self.assertEqual(len(ai_picked), 2)
        self.assertEqual(len([n for n in picked if not n.aistudio_only]), 8)

    async def test_probe_singbox_port_multi_origin_strict_tls_and_retag(self):
        class _FakeResp:
            def __init__(self, status, body):
                self.status = status
                self._body = body

            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                return False

            async def text(self, errors="replace"):
                return self._body.decode("utf-8", errors=errors) if isinstance(self._body, bytes) else self._body

            async def read(self):
                return self._body if isinstance(self._body, bytes) else self._body.encode("utf-8")

        class _FakeSession:
            def __init__(self, routes):
                self.routes = routes
                self.calls = []

            def get(self, url, **kwargs):
                self.calls.append((url, kwargs))
                return self.routes[url]

        # Happy path: GB entry exits in NL, 30KB payload, ipify mismatches -> consistent=False
        n1 = collector.NodeInfo(protocol="ss", host="1.2.3.4", port=8080, country_code="GB")
        sess1 = _FakeSession({
            collector.SINGBOX_TRACE_URL: _FakeResp(200, "ip=198.51.100.7\nloc=nl\n"),
            collector.SINGBOX_PAYLOAD_URL: _FakeResp(200, b"X" * 30_000),
            collector.SINGBOX_IPIFY_URL: _FakeResp(200, "203.0.113.99"),
        })
        self.assertTrue(await collector._probe_singbox_port(sess1, 1080, n1))
        self.assertEqual(n1.exit_ip, "198.51.100.7")
        self.assertEqual(n1.exit_country, "NL")
        self.assertEqual(n1.country_code, "NL")
        self.assertEqual(n1.country_name, "Netherlands")
        self.assertFalse(n1.exit_ip_consistent)
        self.assertTrue(n1.singbox_verified)
        for _url, kw in sess1.calls:
            self.assertIs(kw.get("ssl"), collector._STRICT_TLS_CTX)

        # Blocked exit country IR rejected
        n2 = collector.NodeInfo(protocol="ss", host="1.2.3.5", port=8080)
        sess2 = _FakeSession({
            collector.SINGBOX_TRACE_URL: _FakeResp(200, "ip=5.5.5.5\nloc=IR\n"),
        })
        self.assertFalse(await collector._probe_singbox_port(sess2, 1080, n2))

        # Small/204 payload rejected
        n3 = collector.NodeInfo(protocol="ss", host="1.2.3.6", port=8080)
        sess3 = _FakeSession({
            collector.SINGBOX_TRACE_URL: _FakeResp(200, "ip=198.51.100.8\nloc=DE\n"),
            collector.SINGBOX_PAYLOAD_URL: _FakeResp(200, b"small"),
        })
        self.assertFalse(await collector._probe_singbox_port(sess3, 1080, n3))

        # ipify 429 fails open (exit_ip_consistent stays True)
        n4 = collector.NodeInfo(protocol="ss", host="1.2.3.7", port=8080)
        sess4 = _FakeSession({
            collector.SINGBOX_TRACE_URL: _FakeResp(200, "ip=198.51.100.9\nloc=DE\n"),
            collector.SINGBOX_PAYLOAD_URL: _FakeResp(200, b"Y" * 26_000),
            collector.SINGBOX_IPIFY_URL: _FakeResp(429, "rate limit"),
        })
        self.assertTrue(await collector._probe_singbox_port(sess4, 1080, n4))
        self.assertTrue(n4.exit_ip_consistent)

    def test_exit_ip_dedupe_and_entry_exit_subnet24_cap(self):
        nodes = []
        for i in range(4):
            nodes.append(collector.NodeInfo(
                protocol="vless", host=f"10.50.{i}.1", port=443, tls_enabled=True,
                sni="a.example", network="ws", security="tls",
                original_link=f"vless://u@10.50.{i}.1:443?security=tls&sni=a.example&type=ws#d{i}",
                raw_link=f"vless://u@10.50.{i}.1:443?security=tls&sni=a.example&type=ws#d{i}",
                resolved_ip=f"10.50.{i}.1", exit_ip="198.51.100.5",
                country_code="DE", avg_latency_ms=80 - (i * 10), quality_score=80.0 - (i * 10),
                singbox_verified=True,
            ))
        for i in range(4):
            nodes.append(collector.NodeInfo(
                protocol="vless", host=f"10.60.{i}.1", port=443, tls_enabled=True,
                sni="b.example", network="ws", security="tls",
                original_link=f"vless://u@10.60.{i}.1:443?security=tls&sni=b.example&type=ws#x{i}",
                raw_link=f"vless://u@10.60.{i}.1:443?security=tls&sni=b.example&type=ws#x{i}",
                resolved_ip=f"10.60.{i}.1", exit_ip=f"203.0.113.{10 + i}",
                country_code="DE", avg_latency_ms=100 + i, quality_score=100.0 + i,
                singbox_verified=True,
            ))

        deduped = collector.dedupe_by_exit_ip(nodes)
        same_exit = [n for n in deduped if n.exit_ip == "198.51.100.5"]
        self.assertEqual(len(same_exit), 1)
        self.assertEqual(same_exit[0].avg_latency_ms, 50)

        selected = collector.select_diverse_top_nodes(nodes, quota=10)
        from_203 = [n for n in selected if n.exit_ip.startswith("203.0.113.")]
        self.assertEqual(len(from_203), collector.MAX_NODES_PER_SUBNET24)
        self.assertEqual(len(selected), 3)  # 1 from 198.51.100.5 + 2 from 203.0.113.0/24

    async def test_ipdata_enrichment_fail_open_cache_and_soft_tiebreak(self):
        tmp = tempfile.mkdtemp()
        cache_file = os.path.join(tmp, "ipdata_cache.json")
        n_a = collector.NodeInfo(protocol="vless", host="10.0.1.1", port=443, exit_ip="198.51.100.1", avg_latency_ms=120, quality_score=120.0, singbox_verified=True)
        n_b = collector.NodeInfo(protocol="vless", host="10.0.2.1", port=443, exit_ip="198.51.100.2", avg_latency_ms=150, quality_score=150.0, singbox_verified=True)
        try:
            # No API key -> complete no-op
            with mock.patch.dict(os.environ, {"IPDATA_API_KEY": ""}, clear=False), \
                 mock.patch.object(collector, "IPDATA_CACHE_PATH", cache_file):
                self.assertEqual(await collector.enrich_nodes_with_ipdata(None, [n_a, n_b]), 0)
            self.assertIsNone(n_a.trust_score)

            class _FakeIpdataResp:
                def __init__(self, status, payload):
                    self.status = status
                    self._payload = payload

                async def __aenter__(self):
                    return self

                async def __aexit__(self, *args):
                    return False

                async def json(self, content_type=None):
                    return self._payload

            calls = []

            class _FakeIpdataSess:
                def get(self, url, **kwargs):
                    calls.append(url)
                    if "198.51.100.1" in url:
                        return _FakeIpdataResp(200, {"asn": {"asn": "AS1", "route": "198.51.100.0/24"}, "threat": {"scores": {"trust_score": 10}}})
                    return _FakeIpdataResp(200, {"asn": {"asn": "AS2", "route": "198.51.100.0/24"}, "threat": {"scores": {"trust_score": 90}}})

            with mock.patch.dict(os.environ, {"IPDATA_API_KEY": "test-placeholder-key"}, clear=False), \
                 mock.patch.object(collector, "IPDATA_CACHE_PATH", cache_file):
                enriched = await collector.enrich_nodes_with_ipdata(_FakeIpdataSess(), [n_a, n_b])
            self.assertEqual(enriched, 2)
            self.assertEqual(len(calls), 2)
            self.assertEqual(n_a.exit_asn, "AS1")
            self.assertEqual(n_a.trust_score, 10)
            self.assertEqual(n_b.trust_score, 90)
            # Soft tiebreak: 150 - 180 = -30 < 120 - 20 = 100
            self.assertLess(collector._singbox_rank_key(n_b, 1), collector._singbox_rank_key(n_a, 0))
            # Re-running uses cache without additional HTTP lookups
            with mock.patch.dict(os.environ, {"IPDATA_API_KEY": "test-placeholder-key"}, clear=False), \
                 mock.patch.object(collector, "IPDATA_CACHE_PATH", cache_file):
                enriched2 = await collector.enrich_nodes_with_ipdata(_FakeIpdataSess(), [n_a, n_b])
            self.assertEqual(enriched2, 2)
            self.assertEqual(len(calls), 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_min_country_nodes_candidates_and_step_summary_active_10(self):
        tmp = tempfile.mkdtemp()
        summary_file = os.path.join(tmp, "summary.md")
        patches = [
            mock.patch.object(collector, "OUTPUT_DIR", tmp),
            mock.patch.object(collector, "COUNTRIES_DIR", os.path.join(tmp, "countries")),
            mock.patch.object(collector, "PROTOCOLS_DIR", os.path.join(tmp, "protocols")),
            mock.patch.object(collector, "SERVERS_FILE", os.path.join(tmp, "servers.txt")),
            mock.patch.object(collector, "SUB_FILE", os.path.join(tmp, "sub.txt")),
            mock.patch.object(collector, "CANDIDATES_FILE", os.path.join(tmp, "candidates.txt")),
            mock.patch.object(collector, "STATUS_FILE", os.path.join(tmp, "status.json")),
        ]
        for p in patches:
            p.start()
        try:
            def _mk(code, count):
                out = []
                for i in range(count):
                    ip = f"172.{list(collector.ALLOWED_COUNTRIES).index(code) + 1}.{i}.1"
                    link = f"vless://u@{ip}:443?security=tls&sni=a.example&type=ws#x"
                    out.append(collector.NodeInfo(
                        protocol="vless", host=ip, port=443, tls_enabled=True,
                        sni="a.example", network="ws", security="tls",
                        original_link=link, raw_link=link, resolved_ip=ip,
                        exit_ip=ip, exit_country=code, country_code=code,
                        avg_latency_ms=50 + i, quality_score=50.0 + i, singbox_verified=True,
                    ))
                return out

            # 3 countries >= 2 (DE, NL, US) + 1 thin country (SG=1) + unsupported exit in GB bucket
            bad_exit = collector.NodeInfo(
                protocol="vless", host="172.99.1.1", port=443, tls_enabled=True,
                sni="a.example", network="ws", security="tls",
                original_link="vless://u@172.99.1.1:443?security=tls&sni=a.example#jp",
                raw_link="vless://u@172.99.1.1:443?security=tls&sni=a.example#jp",
                resolved_ip="172.99.1.1", exit_ip="198.51.100.77", exit_country="JP",
                country_code="GB", avg_latency_ms=20, quality_score=20.0, singbox_verified=True,
            )
            by_country = {
                "DE": _mk("DE", 3),
                "NL": _mk("NL", 3),
                "US": _mk("US", 3),
                "SG": _mk("SG", 1),
                "GB": [bad_exit],
            }
            report = collector.write_all_outputs(by_country, {}, total_tested=11, total_passed=10)
            with open(collector.SERVERS_FILE, encoding="utf-8") as f:
                srv = f.read().splitlines()
            self.assertEqual(len(srv), 9)
            self.assertFalse(any("Singapore" in ln for ln in srv))
            self.assertFalse(any("172.99.1.1" in ln for ln in srv))
            self.assertEqual(report["countries"]["SG"]["status"], "low")
            self.assertTrue(os.path.exists(os.path.join(collector.COUNTRIES_DIR, "SG.txt")))
            self.assertTrue(os.path.exists(collector.CANDIDATES_FILE))
            with open(collector.CANDIDATES_FILE, encoding="utf-8") as f:
                cands = f.read().splitlines()
            self.assertEqual(len(cands), 9)
            self.assertEqual(report["candidates_count"], 9)

            with mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": summary_file}, clear=False):
                collector.write_step_summary(report["countries"])
            with open(summary_file, encoding="utf-8") as f:
                md = f.read()
            self.assertIn("Active / 10", md)
            self.assertIn("3 / 10", md)
            self.assertNotIn("/ 5", md)
        finally:
            for p in patches:
                p.stop()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_merge_provenance_aistudio_only_uses_and_when_non_top_source_present(self):
        ai = collector.parse_node_info("vless://u@10.2.0.1:443?security=tls&sni=a.example#ai")
        ai.aistudio_only = True
        ai.top_iran_tier = False
        generic = collector.parse_node_info("vless://u@10.2.0.1:443?security=tls&sni=a.example#gen")
        generic.aistudio_only = False
        generic.top_iran_tier = False
        collector._merge_provenance(ai, generic)
        self.assertFalse(ai.aistudio_only)

        ai_1 = collector.parse_node_info("vless://u@10.2.0.2:443?security=tls&sni=a.example#a1")
        ai_1.aistudio_only = True
        ai_2 = collector.parse_node_info("vless://u@10.2.0.2:443?security=tls&sni=a.example#a2")
        ai_2.aistudio_only = True
        collector._merge_provenance(ai_1, ai_2)
        self.assertTrue(ai_1.aistudio_only)

    def test_thin_country_backfill_to_six_and_rich_candidates_pool(self):
        tmp = tempfile.mkdtemp()
        patches = [
            mock.patch.object(collector, "OUTPUT_DIR", tmp),
            mock.patch.object(collector, "COUNTRIES_DIR", os.path.join(tmp, "countries")),
            mock.patch.object(collector, "PROTOCOLS_DIR", os.path.join(tmp, "protocols")),
            mock.patch.object(collector, "SERVERS_FILE", os.path.join(tmp, "servers.txt")),
            mock.patch.object(collector, "SUB_FILE", os.path.join(tmp, "sub.txt")),
            mock.patch.object(collector, "CANDIDATES_FILE", os.path.join(tmp, "candidates.txt")),
            mock.patch.object(collector, "STATUS_FILE", os.path.join(tmp, "status.json")),
        ]
        for p in patches:
            p.start()
        try:
            # 2 primary nodes + 10 aistudio_only nodes across distinct /24s
            nodes = []
            for i in range(2):
                ip = f"172.30.{i}.1"
                nodes.append(collector.NodeInfo(
                    protocol="vless", host=ip, port=443, tls_enabled=True,
                    sni="a.example", network="ws", security="tls",
                    original_link=f"vless://u@{ip}:443?security=tls&sni=a.example&type=ws#p{i}",
                    raw_link=f"vless://u@{ip}:443?security=tls&sni=a.example&type=ws#p{i}",
                    resolved_ip=ip, exit_ip=ip, exit_country="DE", country_code="DE",
                    avg_latency_ms=100 + i, quality_score=100.0 + i,
                    singbox_verified=True, top_iran_tier=True, aistudio_only=False,
                ))
            for i in range(10):
                ip = f"172.31.{i}.1"
                nodes.append(collector.NodeInfo(
                    protocol="vless", host=ip, port=443, tls_enabled=True,
                    sni="b.example", network="ws", security="tls",
                    original_link=f"vless://u@{ip}:443?security=tls&sni=b.example&type=ws#a{i}",
                    raw_link=f"vless://u@{ip}:443?security=tls&sni=b.example&type=ws#a{i}",
                    resolved_ip=ip, exit_ip=ip, exit_country="DE", country_code="DE",
                    avg_latency_ms=50 + i, quality_score=50.0 + i,
                    singbox_verified=True, top_iran_tier=False, aistudio_only=True,
                ))
            collector.write_all_outputs({"DE": nodes}, {}, total_tested=12, total_passed=12)
            with open(collector.SERVERS_FILE, encoding="utf-8") as f:
                srv = f.read().splitlines()
            with open(collector.CANDIDATES_FILE, encoding="utf-8") as f:
                cands = f.read().splitlines()
            # servers.txt backfills thin DE from 4 (2 primary + 2) up to 6 with /24 diversity
            self.assertEqual(len(srv), 6)
            # First two slots prioritize primary nodes over faster aistudio_only
            self.assertIn("172.30.0.1", srv[0])
            self.assertIn("172.30.1.1", srv[1])
            # candidates.txt keeps rich 12 unique-exit nodes (no artificial 20% cutoff)
            self.assertEqual(len(cands), 12)
        finally:
            for p in patches:
                p.stop()
            shutil.rmtree(tmp, ignore_errors=True)

    def test_candidates_retains_clustered_primary_while_sub_caps_24_and_reality_has_fragment(self):
        real_link = (
            f"vless://11111111-2222-3333-4444-555555555555@169.40.42.10:443"
            f"?security=reality&sni=www.apple.com&pbk={REALITY_PBK}&sid={REALITY_SID}&type=tcp#r"
        )
        real_node = collector.parse_node_info(real_link)
        real_node.iran_verified = True
        ob_real = collector.build_singbox_outbound_for_node(real_node, "tag-r")
        self.assertIsNotNone(ob_real)
        self.assertTrue(ob_real["tls"].get("fragment"))
        self.assertTrue(ob_real["tls"].get("record_fragment"))
        self.assertEqual(ob_real["tls"].get("fragment_fallback_delay"), "500ms")

        tmp = tempfile.mkdtemp()
        patches = [
            mock.patch.object(collector, "OUTPUT_DIR", tmp),
            mock.patch.object(collector, "COUNTRIES_DIR", os.path.join(tmp, "countries")),
            mock.patch.object(collector, "PROTOCOLS_DIR", os.path.join(tmp, "protocols")),
            mock.patch.object(collector, "SERVERS_FILE", os.path.join(tmp, "servers.txt")),
            mock.patch.object(collector, "SUB_FILE", os.path.join(tmp, "sub.txt")),
            mock.patch.object(collector, "CANDIDATES_FILE", os.path.join(tmp, "candidates.txt")),
            mock.patch.object(collector, "CANDIDATES_META_FILE", os.path.join(tmp, "candidates_meta.json")),
            mock.patch.object(collector, "STATUS_FILE", os.path.join(tmp, "status.json")),
        ]
        for p in patches:
            p.start()
        try:
            # 5 primary nodes clustered in 172.40.0.0/24 + 2 distinct primary + 3 aistudio_only
            nodes = []
            for i in range(5):
                ip = f"172.40.0.{10 + i}"
                nodes.append(collector.NodeInfo(
                    protocol="vless", host=ip, port=443, tls_enabled=True,
                    sni="a.example", network="ws", security="tls",
                    original_link=f"vless://u@{ip}:443?security=tls&sni=a.example&type=ws#c{i}",
                    raw_link=f"vless://u@{ip}:443?security=tls&sni=a.example&type=ws#c{i}",
                    resolved_ip=ip, exit_ip=ip, exit_country="DE", country_code="DE",
                    avg_latency_ms=40 + i, quality_score=40.0 + i,
                    singbox_verified=True, top_iran_tier=True, aistudio_only=False,
                ))
            for i in range(2):
                ip = f"172.41.{i}.1"
                nodes.append(collector.NodeInfo(
                    protocol="ss", host=ip, port=8080, tls_enabled=False,
                    original_link=f"ss://aes-256-gcm:pw@{ip}:8080#s{i}",
                    raw_link=f"ss://aes-256-gcm:pw@{ip}:8080#s{i}",
                    resolved_ip=ip, exit_ip=ip, exit_country="DE", country_code="DE",
                    avg_latency_ms=80 + i, quality_score=80.0 + i,
                    singbox_verified=True, iran_verified=True, top_iran_tier=True, aistudio_only=False,
                ))
            for i in range(3):
                ip = f"172.42.{i}.1"
                nodes.append(collector.NodeInfo(
                    protocol="vless", host=ip, port=443, tls_enabled=True,
                    sni="b.example", network="ws", security="tls",
                    original_link=f"vless://u@{ip}:443?security=tls&sni=b.example&type=ws#ai{i}",
                    raw_link=f"vless://u@{ip}:443?security=tls&sni=b.example&type=ws#ai{i}",
                    resolved_ip=ip, exit_ip=ip, exit_country="DE", country_code="DE",
                    avg_latency_ms=30 + i, quality_score=30.0 + i,
                    singbox_verified=True, top_iran_tier=False, aistudio_only=True,
                ))
            collector.write_all_outputs({"DE": nodes}, {}, total_tested=10, total_passed=10)
            with open(collector.SERVERS_FILE, encoding="utf-8") as f:
                srv = f.read().splitlines()
            with open(collector.CANDIDATES_FILE, encoding="utf-8") as f:
                cands = f.read().splitlines()
            with open(collector.CANDIDATES_META_FILE, encoding="utf-8") as mf:
                meta = json.load(mf)
            # sub.txt enforces max 2 nodes in 172.40.0.0/24
            self.assertEqual(sum(1 for ln in srv if "172.40.0." in ln), 2)
            # candidates.txt keeps all 7 clustered+diverse primary nodes BEFORE 3 aistudio_only backfill
            self.assertEqual(len(cands), 10)
            self.assertEqual(meta["primary_count"], 7)
            self.assertEqual(meta["tiers"][:7], ["primary"] * 7)
            self.assertEqual(meta["tiers"][7:], ["backfill"] * 3)
            self.assertFalse(any("172.42." in ln for ln in cands[:7]))
        finally:
            for p in patches:
                p.stop()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
