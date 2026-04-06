# parser/syslog_parser.py
# Parses UFW/iptables-style syslog firewall entries into LogEntry objects.

import re
from datetime import datetime
from parser.base import LogEntry


# Matches UFW BLOCK lines from syslog:
# Dec 10 07:10:01 server kernel: [UFW BLOCK] IN=eth0 SRC=45.33.32.156 ... DPT=22
SYSLOG_PATTERN = re.compile(
    r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)"
    r".*\[UFW BLOCK\].*"
    r"SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+)"
    r".*DPT=(?P<dst_port>\d+)"
)


def parse_syslog(filepath: str) -> list[LogEntry]:
    """
    Reads a syslog file and extracts UFW BLOCK firewall events.
    Returns a list of LogEntry objects with connection metadata.
    """
    entries = []
    current_year = datetime.now().year

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = SYSLOG_PATTERN.search(line)
            if not match:
                continue

            data = match.groupdict()

            try:
                timestamp = datetime.strptime(
                    f"{current_year} {data['month']} {data['day']} {data['time']}",
                    "%Y %b %d %H:%M:%S"
                )
            except ValueError:
                timestamp = None

            entry = LogEntry(
                timestamp=timestamp,
                source_ip=data["src_ip"],
                event_type="firewall_block",
                raw=line,
                metadata={
                    "dst_port": int(data["dst_port"]),
                }
            )
            entries.append(entry)

    return entries