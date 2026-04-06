# detection/anomaly.py
# Detects abnormally high request rates from a single IP.
# Strategy: count requests per IP per minute, flag if over threshold.

from collections import defaultdict
from parser.base import LogEntry
from detection.base import Alert
from config import CONFIG


def detect_anomalies(entries: list[LogEntry]) -> list[Alert]:
    """
    Groups HTTP requests by (source_ip, minute) and alerts
    when any bucket exceeds the configured request rate threshold.
    """
    alerts = []
    threshold = CONFIG["anomaly"]["request_rate_per_minute"]

    # Bucket: ip -> minute_string -> list of entries
    buckets: dict[str, dict[str, list[LogEntry]]] = defaultdict(lambda: defaultdict(list))

    for entry in entries:
        if entry.event_type != "http_request":
            continue
        if not entry.timestamp or not entry.source_ip:
            continue

        minute_key = entry.timestamp.strftime("%Y-%m-%d %H:%M")
        buckets[entry.source_ip][minute_key].append(entry)

    for ip, minutes in buckets.items():
        for minute, reqs in minutes.items():
            if len(reqs) >= threshold:
                alerts.append(Alert(
                    alert_type="ANOMALY_HIGH_REQUEST_RATE",
                    severity="MEDIUM",
                    source_ip=ip,
                    description=(
                        f"{len(reqs)} requests in 1 minute at {minute} "
                        f"(threshold: {threshold})"
                    ),
                    timestamp=reqs[0].timestamp,
                    evidence=[e.raw for e in reqs]
                ))

    return alerts