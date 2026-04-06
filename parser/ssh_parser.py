# parser/ssh_parser.py
# Parses OpenSSH log lines into LogEntry objects.

import re
from datetime import datetime
from parser.base import LogEntry


# Matches lines like:
# Dec 10 06:55:48 server sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
SSH_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
    r".*sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+\w+\s+for\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)


def parse_ssh_log(filepath: str) -> list[LogEntry]:
    """
    Reads an SSH log file and returns a list of LogEntry objects.
    Lines that don't match the expected pattern are skipped silently.
    """
    entries = []
    current_year = datetime.now().year

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = SSH_PATTERN.search(line)
            if not match:
                continue

            data = match.groupdict()

            # Build a timestamp (SSH logs omit the year)
            try:
                timestamp = datetime.strptime(
                    f"{current_year} {data['month']} {data['day']} {data['time']}",
                    "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                timestamp = None

            event_type = (
                "ssh_failed" if data["status"] == "Failed" else "ssh_accepted"
            )

            entry = LogEntry(
                timestamp=timestamp,
                source_ip=data["ip"],
                event_type=event_type,
                raw=line,
                metadata={
                    "user": data["user"],
                    "port": int(data["port"]),
                }
            )
            entries.append(entry)

    return entries