"""Unit tests for collector.py multi-stage pipeline (no network required)."""

import asyncio
import base64
import json
import os
import shutil
import tempfile
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
        calls = {"handshake": 0, "payload": 0}

        async def fake_handshake(n):
            calls["handshake"] += 1
            return True

        async def fake_payload(n):
            calls["payload"] += 1
            return True, 512, 24.0

        with mock.patch.object(
            collector, "_handshake_probe", side_effect=fake_handshake
        ), mock.patch.object(
            collector, "_payload_probe", side_effect=fake_payload
        ):
            result = await collector.verify_node_stability(node)

        self.assertIsNotNone(result)
        self.assertEqual(calls["handshake"], 1)
        self.assertEqual(calls["payload"], 1)
        self.assertEqual(result["payload_bytes"], 512)
        self.assertIsNotNone(node.avg_latency_ms)
        self.assertIsNotNone(node.quality_score)

    async def test_quality_score_formula(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )

        async def fake_handshake(n):
            return True

        async def fake_payload(n):
            return True, 200, 30.0

        with mock.patch.object(
            collector, "_handshake_probe", side_effect=fake_handshake
        ), mock.patch.object(
            collector, "_payload_probe", side_effect=fake_payload
        ):
            result = await collector.verify_node_stability(node)

        self.assertIsNotNone(result)
        expected_avg = round((node.latency_1 + node.latency_2) / 2)
        expected_jitter = round(abs(node.latency_1 - node.latency_2))
        penalty = 0.0 if node.tls_enabled else collector.NON_TLS_PENALTY_MS
        self.assertEqual(node.avg_latency_ms, expected_avg)
        self.assertEqual(node.jitter_ms, expected_jitter)
        self.assertAlmostEqual(
            node.quality_score,
            expected_avg + expected_jitter * 1.5 + penalty,
            places=6,
        )

    async def test_failed_handshake_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )

        async def fake_handshake(n):
            return False

        async def fake_payload(n):
            raise AssertionError("payload probe must not run after handshake failure")

        with mock.patch.object(
            collector, "_handshake_probe", side_effect=fake_handshake
        ), mock.patch.object(
            collector, "_payload_probe", side_effect=fake_payload
        ):
            result = await collector.verify_node_stability(node)

        self.assertIsNone(result)
        self.assertEqual(node.error, "handshake probe failed")
        self.assertIsNone(node.quality_score)

    async def test_failed_payload_probe_dropped(self):
        node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443,
            tls_enabled=False, network="tcp",
            resolved_ip="1.1.1.1",
        )

        async def fake_handshake(n):
            return True

        async def fake_payload(n):
            return False, 0, 20.0

        with mock.patch.object(
            collector, "_handshake_probe", side_effect=fake_handshake
        ), mock.patch.object(
            collector, "_payload_probe", side_effect=fake_payload
        ):
            result = await collector.verify_node_stability(node)

        self.assertIsNone(result)
        self.assertEqual(node.error, "payload probe failed")
        self.assertIsNone(node.quality_score)

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
            return {ip: "CA" for ip in ips}

        collector.reset_mmdb_state()
        with mock.patch.object(
            collector, "_batch_geoip_with_retry", side_effect=fake_batch
        ):
            allowed = await collector.filter_by_geoip(_DummySession(), nodes)

        self.assertEqual(seen["ips"], ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(len(allowed), 2)
        self.assertTrue(all(n.country_code == "CA" for n in allowed))

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
            collector, "resolve_and_dedup_nodes", side_effect=fake_resolve
        ), mock.patch.object(
            collector, "ensure_mmdb_database", side_effect=fake_ensure
        ), mock.patch.object(
            collector, "filter_by_geoip", side_effect=fake_geoip
        ), mock.patch.object(
            collector, "verify_node_stability", side_effect=fake_probe
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
    """D4: sources.txt must hold exactly six live subscription mirrors."""
    """D4: sources.txt must hold exactly ten live subscription mirrors."""

    def test_no_dead_urls(self):
        with open(collector.SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        self.assertEqual(len(urls), 6)
        self.assertEqual(len(urls), 10)
        for dead in (
            "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Sub1.txt",
            "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/"
            "All_Configs_Sub.txt",
            "https://raw.githubusercontent.com/epodonios/v2ray-configs/main/"
            "All_Configs_Sub.txt",
            "https://raw.githubusercontent.com/soroushmirzaei/"
            "telegram-configs-collector/main/channels/configs",
        ):
            self.assertNotIn(dead, urls)

    def test_keeps_working_high_yield_mirrors(self):
        with open(collector.SOURCES_FILE, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f if line.strip()]
        for live in (
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/mci_top100.txt",
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/irancell_top100.txt",
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/tci_top100.txt",
            "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/"
            "main/output_iran/iran_top100_checked.txt",
            "https://raw.githubusercontent.com/MohammadBahemmat/"
            "V2ray-Collector/main/all_servers.txt",
            "https://raw.githubusercontent.com/mahdibland/"
            "V2RayAggregator/master/sub/sub_merge.txt",
            "https://raw.githubusercontent.com/Danialsamadi/v2go/main/Sub1.txt",
            "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/"
            "main/config/all_configs.txt",
            "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
            "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/"
            "subscribe/v2ray.txt",
        ):
            self.assertIn(live, urls)


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
            "&amp;type=tcp#a\n"
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
        self.assertIn("🇩🇪 Germany 01 | VLESS | ⚡ 30ms | BrickVPN", link)


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
        async def fake_handshake(n):
            return True

        async def fake_payload(n):
            return True, 128, 40.0

        tls_node = collector.NodeInfo(
            protocol="vless", host="1.1.1.1", port=443, tls_enabled=True,
            network="tcp", resolved_ip="1.1.1.1",
        )
        plain_node = collector.NodeInfo(
            protocol="ss", host="2.2.2.2", port=8388, tls_enabled=False,
            network="tcp", resolved_ip="2.2.2.2",
        )

        with mock.patch.object(
            collector, "_handshake_probe", side_effect=fake_handshake
        ), mock.patch.object(
            collector, "_payload_probe", side_effect=fake_payload
        ):
            await collector.verify_node_stability(tls_node)
            await collector.verify_node_stability(plain_node)

        self.assertLess(tls_node.quality_score, plain_node.quality_score)
        self.assertAlmostEqual(
            plain_node.quality_score - tls_node.quality_score,
            collector.NON_TLS_PENALTY_MS,
            delta=2.0,
        )


class TestLatencyCapAndIpDiversity(unittest.IsolatedAsyncioTestCase):
    """B3: MAX_LATENCY_MS cap and one node per unique IP per country."""

    async def test_slow_node_dropped(self):
        async def fake_handshake(n):
            return True

        async def fake_payload(n):
            return True, 64, float(collector.MAX_LATENCY_MS * 2 + 200)

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

        self.assertIsNone(result)
        self.assertIn("cap", node.error)
        self.assertIsNone(node.quality_score)

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
            node = collector.NodeInfo(
                protocol="vless", host=f"10.0.0.{i + 1}", port=443,
                resolved_ip=f"10.0.0.{i + 1}", country_code="DE",
                quality_score=float(i), avg_latency_ms=10 + i,
            )
            nodes.append(node)
        return nodes

    def test_numbering_restarts_per_output_list(self):
        nodes = self._build_nodes(7)
        report = collector.write_all_outputs(
            {"DE": nodes}, {}, total_tested=12, total_passed=7
        )

        with open(collector.SERVERS_FILE, encoding="utf-8") as f:
            server_lines = f.read().splitlines()
        self.assertEqual(len(server_lines), collector.MAIN_QUOTA_PER_COUNTRY)
        for idx, line in enumerate(server_lines, start=1):
            self.assertIn(f"Germany {idx:02d} |", line)

        with open(os.path.join(collector.COUNTRIES_DIR, "DE.txt"), encoding="utf-8") as f:
            country_lines = f.read().splitlines()
        self.assertEqual(len(country_lines), 7)
        for idx, line in enumerate(country_lines, start=1):
            self.assertIn(f"Germany {idx:02d} |", line)

        self.assertEqual(report["main_sub_count"], collector.MAIN_QUOTA_PER_COUNTRY)
        self.assertEqual(report["total_tested"], 12)
        self.assertEqual(report["total_passed"], 7)
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


if __name__ == "__main__":
    unittest.main()
