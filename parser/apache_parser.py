# parser/apache_parser.py
# Parses Apache Combined Log Format into LogEntry objects.

import re
from datetime import datetime
from parser.base import LogEntry


# Matches Apache Combined Log Format:
# 192.168.1.1 - - [10/Dec/2026:07:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
APACHE_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r'\s+-\s+-\s+'
    r'\[(?P<time>[^\]]+)\]'
    r'\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"'
    r'\s+(?P<status>\d+)'
    r'\s+(?P<size>\d+)'
    r'\s+"[^"]*"'
    r'\s+"(?P<user_agent>[^"]*)"'
)

APACHE_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


def parse_apache_log(filepath: str) -> list[LogEntry]:
    """
    Reads an Apache Combined Log Format file.
    Returns a list of LogEntry objects.
    Lines that don't match are skipped silently.
    """
    entries = []

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            match = APACHE_PATTERN.search(line)
            if not match:
                continue

            data = match.groupdict()

            try:
                timestamp = datetime.strptime(data["time"], APACHE_TIME_FORMAT)
            except ValueError:
                timestamp = None

            entry = LogEntry(
                timestamp=timestamp,
                source_ip=data["ip"],
                event_type="http_request",
                raw=line,
                metadata={
                    "method":     data["method"],
                    "path":       data["path"],
                    "status":     int(data["status"]),
                    "size":       int(data["size"]),
                    "user_agent": data["user_agent"],
                }
            )
            entries.append(entry)

    return entries