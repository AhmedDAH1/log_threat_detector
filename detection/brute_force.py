# detection/brute_force.py
# Detects brute force login attempts based on failed SSH logins.
# Strategy: sliding time window per source IP.

from collections import defaultdict
from datetime import timedelta
from parser.base import LogEntry
from detection.base import Alert
from config import CONFIG


def detect_brute_force(entries: list[LogEntry]) -> list[Alert]:
    """
    Scans LogEntry objects for brute force patterns.
    Only processes ssh_failed events.
    Returns a list of Alert objects.
    """
    alerts = []
    cfg = CONFIG["brute_force"]
    max_attempts = cfg["max_failed_attempts"]
    window = timedelta(seconds=cfg["time_window_seconds"])

    # Group failed attempts by source IP
    failures: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.event_type == "ssh_failed" and entry.source_ip and entry.timestamp:
            failures[entry.source_ip].append(entry)

    for ip, events in failures.items():
        # Sort by time so our sliding window works correctly
        events.sort(key=lambda e: e.timestamp)

        # Sliding window: for each event, count how many fall within the window
        for i, event in enumerate(events):
            window_events = [
                e for e in events[i:]
                if e.timestamp - event.timestamp <= window
            ]

            if len(window_events) >= max_attempts:
                users = set(e.metadata.get("user", "?") for e in window_events)
                alerts.append(Alert(
                    alert_type="BRUTE_FORCE",
                    severity="HIGH",
                    source_ip=ip,
                    description=(
                        f"{len(window_events)} failed login attempts in "
                        f"{cfg['time_window_seconds']}s "
                        f"targeting user(s): {', '.join(users)}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[e.raw for e in window_events]
                ))
                break  # one alert per IP, avoid duplicates

    return alerts