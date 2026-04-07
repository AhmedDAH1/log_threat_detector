# detection/watch_mode.py
# Tails a log file in real time and runs detection on each new line.

import time
import os
from colorama import Fore, Style, init

from parser.ssh_parser import parse_ssh_log
from parser.apache_parser import parse_apache_log
from parser.syslog_parser import parse_syslog

from detection.brute_force import detect_brute_force
from detection.user_agent import detect_suspicious_user_agents
from detection.anomaly import detect_anomalies
from detection.port_scan import detect_port_scan

from output.alert_output import print_alerts

init(autoreset=True)

PARSERS = {
    "ssh":    parse_ssh_log,
    "apache": parse_apache_log,
    "syslog": parse_syslog,
}

DETECTORS = {
    "ssh":    [detect_brute_force],
    "apache": [detect_suspicious_user_agents, detect_anomalies],
    "syslog": [detect_port_scan],
}


def detect_log_type(filepath: str) -> str:
    """Infer log type from filename."""
    name = os.path.basename(filepath).lower()
    if "ssh" in name:
        return "ssh"
    if "apache" in name or "access" in name:
        return "apache"
    if "syslog" in name or "kern" in name:
        return "syslog"
    raise ValueError(
        f"Cannot infer log type from filename '{name}'. "
        f"Use a filename containing 'ssh', 'apache', or 'syslog'."
    )


def watch(filepath: str, interval: float = 1.0) -> None:
    """
    Tails a log file and runs all relevant detections
    on the full file every time new lines are added.
    Reruns detection on cumulative content so sliding
    windows stay accurate.
    """
    log_type = detect_log_type(filepath)
    parser = PARSERS[log_type]
    detectors = DETECTORS[log_type]

    print(Style.BRIGHT + f"\n👁  Watching {filepath} [{log_type}] — press Ctrl+C to stop\n")

    last_size = 0
    seen_alerts = set()

    try:
        while True:
            current_size = os.path.getsize(filepath)

            if current_size > last_size:
                last_size = current_size

                # Parse full file each time — keeps sliding window accurate
                entries = parser(filepath)
                if not entries:
                    continue

                for detector in detectors:
                    alerts = detector(entries)
                    for alert in alerts:
                        # Deduplicate — only show each alert once
                        key = (alert.alert_type, alert.source_ip, str(alert.timestamp))
                        if key not in seen_alerts:
                            seen_alerts.add(key)
                            print_alerts([alert])

            time.sleep(interval)

    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n  Watch mode stopped.")