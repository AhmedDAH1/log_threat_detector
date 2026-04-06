# detection/base.py
# Shared Alert model returned by all detection modules.

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    alert_type: str         # e.g. "BRUTE_FORCE", "PORT_SCAN"
    severity: str           # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    source_ip: str
    description: str
    timestamp: datetime
    evidence: list          # the raw log lines that triggered this alert