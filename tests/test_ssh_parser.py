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