# detection/port_scan.py
# Detects port scanning based on firewall block events.
# Strategy: if one IP hits more than N unique ports within a time window, flag it.

from collections import defaultdict
from datetime import timedelta
from parser.base import LogEntry
from detection.base import Alert
from config import CONFIG


def detect_port_scan(entries: list[LogEntry]) -> list[Alert]:
    """
    Scans firewall_block LogEntry objects for port scan patterns.
    Returns a list of Alert objects.
    """
    alerts = []
    cfg = CONFIG["port_scan"]
    max_ports = cfg["max_ports"]
    window = timedelta(seconds=cfg["time_window_seconds"])

    # Group firewall block events by source IP
    blocks: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        if entry.event_type == "firewall_block" and entry.source_ip and entry.timestamp:
            blocks[entry.source_ip].append(entry)

    for ip, events in blocks.items():
        events.sort(key=lambda e: e.timestamp)

        # Sliding window: collect unique ports hit within the window
        for i, event in enumerate(events):
            window_events = [
                e for e in events[i:]
                if e.timestamp - event.timestamp <= window
            ]

            unique_ports = set(e.metadata["dst_port"] for e in window_events)

            if len(unique_ports) >= max_ports:
                alerts.append(Alert(
                    alert_type="PORT_SCAN",
                    severity="HIGH",
                    source_ip=ip,
                    description=(
                        f"{len(unique_ports)} unique ports probed in "
                        f"{cfg['time_window_seconds']}s: "
                        f"{sorted(unique_ports)}"
                    ),
                    timestamp=event.timestamp,
                    evidence=[e.raw for e in window_events]
                ))
                break  # one alert per IP

    return alerts