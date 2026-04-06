# detection/user_agent.py
# Detects requests from known malicious or suspicious user agents.

from parser.base import LogEntry
from detection.base import Alert
from config import CONFIG


def detect_suspicious_user_agents(entries: list[LogEntry]) -> list[Alert]:
    """
    Flags any HTTP request whose User-Agent matches a known bad tool.
    One alert per unique (IP, user_agent) pair.
    """
    alerts = []
    bad_agents = CONFIG["suspicious_user_agents"]
    seen = set()

    for entry in entries:
        if entry.event_type != "http_request":
            continue

        ua = entry.metadata.get("user_agent", "").lower()
        matched = next((b for b in bad_agents if b.lower() in ua), None)

        if not matched:
            continue

        key = (entry.source_ip, matched)
        if key in seen:
            continue
        seen.add(key)

        alerts.append(Alert(
            alert_type="SUSPICIOUS_USER_AGENT",
            severity="MEDIUM",
            source_ip=entry.source_ip,
            description=f"Malicious tool detected in User-Agent: '{matched}'",
            timestamp=entry.timestamp,
            evidence=[entry.raw]
        ))

    return alerts