# tests/test_analysis_api.py
# The HTTP API SOAR-Lite calls to analyse uploaded logs.

import unittest

from analysis_api import app

SSH = "\n".join(
    f"Dec 10 06:55:{48 + i} server sshd[1234]: Failed password for root from 203.0.113.7 port 22 ssh2"
    for i in range(6)
)
SYSLOG = "\n".join(
    f"Dec 10 07:10:01 server kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.7 DST=10.0.0.1 PROTO=TCP SPT=5432 DPT={p}"
    for p in range(20, 40)
)
APACHE = '203.0.113.9 - - [10/Dec/2026:07:00:03 +0000] "GET /login HTTP/1.1" 200 128 "-" "sqlmap/1.4"'


class AnalysisApiTest(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def analyze(self, logs):
        return self.client.post("/api/analyze", json={"logs": logs})

    def test_log_type_is_detected_and_alerts_use_the_soar_format(self):
        response = self.analyze([{"name": "auth.log", "content": SSH}])
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["logs"][0]["type"], "ssh")
        self.assertEqual(data["logs"][0]["entries"], 6)
        alert = data["alerts"][0]
        self.assertEqual(alert["result"]["alert_type"], "BRUTE_FORCE")
        self.assertEqual(alert["result"]["src_ip"], "203.0.113.7")
        self.assertIn("search_name", alert)          # SOAR-Lite's SIEM webhook format

    def test_correlation_runs_across_logs_in_one_request(self):
        data = self.analyze([{"name": "auth.log", "content": SSH}, {"name": "ufw.log", "content": SYSLOG}]).get_json()
        types = {a["result"]["alert_type"] for a in data["alerts"]}
        self.assertIn("COORDINATED_ATTACK", types)
        self.assertEqual(data["correlated"], 1)

    def test_explicit_type_and_web_log(self):
        data = self.analyze([{"name": "access.log", "content": APACHE, "type": "apache"}]).get_json()
        self.assertEqual(data["alerts"][0]["result"]["alert_type"], "SUSPICIOUS_USER_AGENT")

    def test_unrecognised_text_gives_no_alerts(self):
        data = self.analyze([{"name": "notes.txt", "content": "hello\nworld"}]).get_json()
        self.assertEqual(data["alerts"], [])
        self.assertIsNone(data["logs"][0]["type"])

    def test_bad_requests_are_refused(self):
        self.assertEqual(self.client.post("/api/analyze", json={}).status_code, 400)
        self.assertEqual(self.analyze([{"name": "x"}]).status_code, 400)
        self.assertEqual(self.analyze([{"content": "x", "type": "windows"}]).status_code, 400)
        self.assertEqual(self.analyze([{"content": "x" * (6 * 1024 * 1024)}]).status_code in (400, 413), True)

    def test_health(self):
        self.assertEqual(self.client.get("/health").get_json(), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
