"""Unit tests for collector.py logic (no network required)."""

import asyncio
import base64
import json
import unittest
from unittest import mock

import collector


class TestParseHostPort(unittest.TestCase):
    def test_vmess(self):
        cfg = {"add": "1.2.3.4", "port": 8080}
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        self.assertEqual(collector.parse_host_port(link), ("1.2.3.4", "8080"))

    def test_vmess_missing_fields(self):
        # Port missing -> unparseable
        cfg = {"add": "1.2.3.4"}
        link = "vmess://" + base64.b64encode(json.dumps(cfg).encode()).decode()
        self.assertEqual(collector.parse_host_port(link), (None, None))

    def test_vless(self):
        self.assertEqual(
            collector.parse_host_port("vless://uuid@5.6.7.8:443"), ("5.6.7.8", "443")
        )

    def test_trojan(self):
        self.assertEqual(
            collector.parse_host_port("trojan://pass@9.9.9.9:443"),
            ("9.9.9.9", "443"),
        )

    def test_ss(self):
        self.assertEqual(
            collector.parse_host_port("ss://aes-256-gcm:pw@1.1.1.1:8388"),
            ("1.1.1.1", "8388"),
        )

    def test_non_proxy_link(self):
        self.assertEqual(collector.parse_host_port("http://example.com"), (None, None))
        self.assertEqual(collector.parse_host_port("notalink"), (None, None))
        self.assertEqual(collector.parse_host_port(""), (None, None))


class TestExtractLinks(unittest.TestCase):
    def test_plain_text(self):
        text = "vless://u@1.1.1.1:443\ntrojan://p@2.2.2.2:443"
        links = collector.extract_links(text)
        self.assertIn("vless://u@1.1.1.1:443", links)
        self.assertIn("trojan://p@2.2.2.2:443", links)

    def test_embedded_in_html(self):
        html = '<a href="vless://u@3.3.3.3:443">click</a> trojan://p@4.4.4.4:443'
        links = collector.extract_links(html)
        self.assertIn("vless://u@3.3.3.3:443", links)
        self.assertIn("trojan://p@4.4.4.4:443", links)

    def test_base64_subscription(self):
        raw = "vless://u@5.5.5.5:443\ntrojan://p@6.6.6.6:443"
        b64 = base64.b64encode(raw.encode()).decode()
        links = collector.extract_links(b64)
        self.assertIn("vless://u@5.5.5.5:443", links)
        self.assertIn("trojan://p@6.6.6.6:443", links)

    def test_empty(self):
        self.assertEqual(collector.extract_links(""), [])
        self.assertEqual(collector.extract_links("no links here"), [])


class TestDeduplicate(unittest.TestCase):
    def test_drops_ip_port_duplicates(self):
        links = [
            "vless://u@1.2.3.4:443",
            "vless://u2@1.2.3.4:443",  # same IP:Port -> dup
            "vmess://"
            + base64.b64encode(
                json.dumps({"add": "5.6.7.8", "port": 8080}).encode()
            ).decode(),
            "ss://m:pw@1.1.1.1:8388",
            "ss://m:pw@1.1.1.1:8388",  # dup
        ]
        uniq = collector.deduplicate(links)
        self.assertEqual(len(uniq), 3)

    def test_drops_unparseable(self):
        # Unparseable links all map to (None, None) -> only one kept at most,
        # but per the fix they should be dropped entirely downstream.
        links = ["http://example.com", "notalink", "vless://u@1.2.3.4:443"]
        uniq = collector.deduplicate(links)
        # deduplicate keeps first of each key; (None,None) collapses unparseables
        self.assertIn("vless://u@1.2.3.4:443", uniq)


class TestTestNodes(unittest.IsolatedAsyncioTestCase):
    async def test_drops_unparseable_and_failed(self):
        async def fake_tcp_ping(host, port, timeout=3.0):
            return (host, port) == ("1.1.1.1", 443)

        with mock.patch.object(collector, "tcp_ping", side_effect=fake_tcp_ping):
            links = [
                "vless://u@1.1.1.1:443",   # parseable + up
                "trojan://p@2.2.2.2:443",   # parseable + down
                "http://example.com",       # unparseable -> must be dropped
                "notalink",                 # unparseable -> must be dropped
            ]
            active = await collector.test_nodes(links)
        self.assertEqual(active, ["vless://u@1.1.1.1:443"])

    async def test_empty_input(self):
        self.assertEqual(await collector.test_nodes([]), [])


if __name__ == "__main__":
    unittest.main()
