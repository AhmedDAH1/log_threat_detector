# tests/test_soar_forwarder.py
# Forwarding alerts to SOAR-Lite: the payload format, the request signature
# SOAR-Lite verifies, and that a SOAR-Lite outage never stops detection.

import hashlib
import hmac
import json
import threading
import time
import unittest
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from detection.base import Alert
from output.soar_forwarder import SoarForwarder, alert_payload, sign

SECRET = "shared-secret"


def make_alert(**overrides) -> Alert:
    fields = dict(
        alert_type="BRUTE_FORCE", severity="HIGH", source_ip="203.0.113.7",
        description="6 failed login attempts in 60s targeting user(s): root",
        timestamp=datetime(2026, 11, 8, 1, 0, 0),
        evidence=[f"line {i}" for i in range(30)],
    )
    fields.update(overrides)
    return Alert(**fields)


class FakeSoarLite(BaseHTTPRequestHandler):
    """Records requests and answers like SOAR-Lite's webhook endpoint."""
    requests = []
    status = 201

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakeSoarLite.requests.append((self.path, dict(self.headers), body))
        self.send_response(FakeSoarLite.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"incident_id": 42}).encode())

    def log_message(self, *args):
        pass


class TestPayload(unittest.TestCase):

    def test_matches_soar_lite_siem_format(self):
        payload = alert_payload(make_alert())
        self.assertEqual(payload["search_name"], "BRUTE_FORCE from 203.0.113.7")
        self.assertEqual(payload["severity"], "high")
        self.assertIn("203.0.113.7", payload["description"])   # SOAR-Lite extracts IOCs from text
        self.assertEqual(payload["result"]["src_ip"], "203.0.113.7")
        self.assertEqual(payload["result"]["detector"], "log_threat_detector")

    def test_evidence_is_capped(self):
        result = alert_payload(make_alert())["result"]
        self.assertEqual(len(result["evidence"]), 20)
        self.assertEqual(result["evidence_total"], 30)

    def test_alert_without_timestamp(self):
        self.assertIsNone(alert_payload(make_alert(timestamp=None))["result"]["timestamp"])


class TestSignature(unittest.TestCase):

    def test_signature_matches_soar_lite_scheme(self):
        # Computed independently: HMAC-SHA256 over "<timestamp>." + body
        body, ts = b'{"a": 1}', 1700000000
        expected = hmac.new(SECRET.encode(), b"1700000000." + body, hashlib.sha256).hexdigest()
        self.assertEqual(sign(body, SECRET, ts), "sha256=" + expected)

    def test_different_body_gives_different_signature(self):
        self.assertNotEqual(sign(b"a", SECRET, 1), sign(b"b", SECRET, 1))


class TestConfiguration(unittest.TestCase):

    def test_secret_is_required(self):
        with self.assertRaises(ValueError):
            SoarForwarder("http://localhost:8000", "")

    def test_only_http_urls(self):
        for url in ("ftp://host", "localhost:8000", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                SoarForwarder(url, SECRET)

    def test_posts_to_the_siem_webhook(self):
        self.assertEqual(SoarForwarder("http://soar:8000/", SECRET).url, "http://soar:8000/api/webhooks/siem")


class TestSending(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), FakeSoarLite)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        FakeSoarLite.requests = []
        FakeSoarLite.status = 201

    def test_sends_a_signed_request(self):
        self.assertTrue(SoarForwarder(self.url, SECRET).send(make_alert()))
        path, headers, body = FakeSoarLite.requests[0]
        self.assertEqual(path, "/api/webhooks/siem")
        ts = int(headers["X-Webhook-Timestamp"])
        self.assertLess(abs(time.time() - ts), 5)
        self.assertEqual(headers["X-Webhook-Signature"], sign(body, SECRET, ts))
        self.assertEqual(json.loads(body)["search_name"], "BRUTE_FORCE from 203.0.113.7")

    def test_refused_alert_is_reported_not_raised(self):
        FakeSoarLite.status = 401
        self.assertFalse(SoarForwarder(self.url, SECRET).send(make_alert()))

    def test_soar_lite_down_does_not_stop_detection(self):
        # Nothing listens on port 9 (discard); send must return, not raise.
        self.assertFalse(SoarForwarder("http://127.0.0.1:9", SECRET).send(make_alert()))

    def test_send_all_counts_accepted_alerts(self):
        alerts = [make_alert(source_ip=f"203.0.113.{i}") for i in range(3)]
        self.assertEqual(SoarForwarder(self.url, SECRET).send_all(alerts), 3)


if __name__ == "__main__":
    unittest.main()
