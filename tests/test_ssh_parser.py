# tests/test_ssh_parser.py
import unittest
from datetime import datetime
from unittest.mock import mock_open, patch
from parser.ssh_parser import parse_ssh_log


SAMPLE_SSH_LOGS = """Dec 10 06:55:48 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Dec 10 06:55:49 server sshd[1234]: Accepted password for deploy from 10.0.0.2 port 22 ssh2
Dec 10 06:55:50 server sshd[1234]: This line does not match and should be skipped
"""


class TestSSHParser(unittest.TestCase):

    def setUp(self):
        with patch("builtins.open", mock_open(read_data=SAMPLE_SSH_LOGS)):
            self.entries = parse_ssh_log("fake/path.log")

    def test_correct_entry_count(self):
        """Only matching lines should be parsed — unrecognized lines skipped."""
        self.assertEqual(len(self.entries), 2)

    def test_failed_login_event_type(self):
        self.assertEqual(self.entries[0].event_type, "ssh_failed")

    def test_accepted_login_event_type(self):
        self.assertEqual(self.entries[1].event_type, "ssh_accepted")

    def test_source_ip_extracted(self):
        self.assertEqual(self.entries[0].source_ip, "192.168.1.105")
        self.assertEqual(self.entries[1].source_ip, "10.0.0.2")

    def test_username_in_metadata(self):
        self.assertEqual(self.entries[0].metadata["user"], "root")
        self.assertEqual(self.entries[1].metadata["user"], "deploy")

    def test_port_in_metadata(self):
        self.assertEqual(self.entries[0].metadata["port"], 22)

    def test_timestamp_is_datetime(self):
        self.assertIsInstance(self.entries[0].timestamp, datetime)

    def test_raw_line_preserved(self):
        self.assertIn("192.168.1.105", self.entries[0].raw)


if __name__ == "__main__":
    unittest.main()

class TestInvalidUserLogins(unittest.TestCase):
    """Brute-force attacks mostly guess usernames that don't exist, which
    sshd logs as "Failed password for invalid user <name>". These lines used
    to be skipped, so the most common attack produced no alert."""

    def _parse(self, lines):
        import os
        import tempfile
        from parser.ssh_parser import parse_ssh_log
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write("\n".join(lines) + "\n")
        try:
            return parse_ssh_log(f.name)
        finally:
            os.unlink(f.name)

    def test_invalid_user_line_is_parsed(self):
        entries = self._parse([
            "Dec 10 06:55:48 server sshd[1234]: Failed password for invalid user admin from 203.0.113.7 port 4242 ssh2"
        ])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].metadata["user"], "admin")
        self.assertTrue(entries[0].metadata["invalid_user"])
        self.assertEqual(entries[0].source_ip, "203.0.113.7")

    def test_brute_force_with_invalid_users_is_detected(self):
        from detection.brute_force import detect_brute_force
        lines = [
            f"Dec 10 06:55:{i:02d} server sshd[1234]: Failed password for invalid user user{i} "
            f"from 203.0.113.7 port {4000 + i} ssh2"
            for i in range(6)
        ]
        alerts = detect_brute_force(self._parse(lines))
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source_ip, "203.0.113.7")

    def test_valid_user_still_parsed(self):
        entries = self._parse([
            "Dec 10 06:55:48 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2"
        ])
        self.assertEqual(entries[0].metadata["user"], "root")
        self.assertFalse(entries[0].metadata["invalid_user"])

    def test_username_cannot_carry_terminal_escape_codes(self):
        # The attacker picks the username; an ANSI sequence could rewrite the analyst's terminal.
        entries = self._parse([
            "Dec 10 06:55:48 server sshd[1234]: Failed password for invalid user ad\x1b[2Jmin "
            "from 203.0.113.7 port 22 ssh2"
        ])
        self.assertNotIn("\x1b", entries[0].metadata["user"])
