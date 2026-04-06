# parser/base.py
# Shared data model for all parsed log entries.
# Every parser must return a list of LogEntry objects.

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class LogEntry:
    timestamp: Optional[datetime]   # when the event happened
    source_ip: Optional[str]        # originating IP address
    event_type: str                 # e.g. "ssh_failed", "http_request"
    raw: str                        # original log line, unmodified
    metadata: dict = field(default_factory=dict)  # flexible extra fields