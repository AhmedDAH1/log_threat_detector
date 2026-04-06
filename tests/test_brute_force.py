# tests/test_brute_force.py
import unittest
from datetime import datetime, timedelta
from parser.base import LogEntry
from detection.brute_force import detect_brute_force


def make_failed_entry(ip: str, seconds_offset: int, user: str = "root") -> LogEntry:
    """Helper to build a synthetic ssh_failed LogEntry."""
    return LogEntry(
        timestamp=datetime(2026, 12, 10, 6, 55, 0) + timedelta(seconds=seconds_offset),
        source_ip=ip,
        event_type="ssh_failed",
        raw=f"Dec 10 06:55:{seconds_offset:02d} sshd: Failed password for {user} from {ip}",
        metadata={"user": user, "port": 22}
    )


class TestBruteForceDetection(unittest.TestCase):

    def test_triggers_above_threshold(self):
        """6 failures from same IP within 60s should trigger an alert."""
        entries = [make_failed_entry("1.2.3.4", i) for i in range(6)]
        alerts = detect_brute_force(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "BRUTE_FORCE")
        self.assertEqual(alerts[0].source_ip, "1.2.3.4")
        self.assertEqual(alerts[0].severity, "HIGH")

    def test_no_alert_below_threshold(self):
        """4 failures should not trigger — below threshold of 5."""
        entries = [make_failed_entry("1.2.3.4", i) for i in range(4)]
        alerts = detect_brute_force(entries)
        self.assertEqual(len(alerts), 0)

    def test_no_alert_outside_time_window(self):
        """6 failures spread over 10 minutes should not trigger (window is 60s)."""
        entries = [make_failed_entry("1.2.3.4", i * 120) for i in range(6)]
        alerts = detect_brute_force(entries)
        self.assertEqual(len(alerts), 0)

    def test_different_ips_isolated(self):
        """Failures from different IPs should not be combined."""
        entries = (
            [make_failed_entry("1.1.1.1", i) for i in range(6)] +
            [make_failed_entry("2.2.2.2", i) for i in range(3)]
        )
        alerts = detect_brute_force(entries)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "1.1.1.1")

    def test_accepted_logins_ignored(self):
        """ssh_accepted events must never count toward brute force."""
        entries = [
            LogEntry(
                timestamp=datetime(2026, 12, 10, 6, 55, i),
                source_ip="1.2.3.4",
                event_type="ssh_accepted",
                raw="accepted line",
                metadata={"user": "root", "port": 22}
            )
            for i in range(6)
        ]
        alerts = detect_brute_force(entries)
        self.assertEqual(len(alerts), 0)

    def test_one_alert_per_ip(self):
        """Even with 20 failures, only one alert should fire per IP."""
        entries = [make_failed_entry("1.2.3.4", i) for i in range(20)]
        alerts = detect_brute_force(entries)
        self.assertEqual(len(alerts), 1)


if __name__ == "__main__":
    unittest.main()