# detection/correlation.py
# Correlates alerts across multiple detection modules.
# Strategy: group alerts by source IP, detect multi-vector attacks,
# and escalate severity when the same IP triggers multiple threat types.

from collections import defaultdict
from detection.base import Alert
from datetime import datetime


# Threat combinations and what they mean
CORRELATION_RULES = [
    {
        "required": {"BRUTE_FORCE", "PORT_SCAN"},
        "attack_type": "COORDINATED_ATTACK",
        "description": "Same IP performed both brute force login attempts and port scanning — active intrusion attempt.",
    },
    {
        "required": {"PORT_SCAN", "SUSPICIOUS_USER_AGENT"},
        "attack_type": "RECONNAISSANCE",
        "description": "Same IP performed port scanning and used a known attack tool — active reconnaissance.",
    },
    {
        "required": {"BRUTE_FORCE", "SUSPICIOUS_USER_AGENT"},
        "attack_type": "TARGETED_ATTACK",
        "description": "Same IP performed brute force login attempts and used a known attack tool — targeted attack.",
    },
    {
        "required": {"BRUTE_FORCE", "PORT_SCAN", "SUSPICIOUS_USER_AGENT"},
        "attack_type": "FULL_COMPROMISE_ATTEMPT",
        "description": "Same IP triggered all major attack vectors — full compromise attempt in progress.",
    },
]


def correlate_alerts(alerts: list[Alert]) -> list[Alert]:
    """
    Groups alerts by source IP and checks for multi-vector attack patterns.
    Returns a list of new CRITICAL correlated alerts.
    Original alerts are not modified.
    """
    correlated = []

    # Group alerts by source IP
    by_ip: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        if alert.source_ip:
            by_ip[alert.source_ip].append(alert)

    for ip, ip_alerts in by_ip.items():
        # Only correlate IPs with more than one alert type
        if len(ip_alerts) < 2:
            continue

        alert_types = {a.alert_type for a in ip_alerts}

        for rule in CORRELATION_RULES:
            if not rule["required"].issubset(alert_types):
                continue

            # Collect all evidence from contributing alerts
            all_evidence = []
            contributing = []
            for a in ip_alerts:
                if a.alert_type in rule["required"]:
                    all_evidence.extend(a.evidence)
                    contributing.append(f"{a.alert_type} ({a.severity})")

            def strip_tz(ts):
                return ts.replace(tzinfo=None) if ts.tzinfo else ts

            earliest = min(
                (strip_tz(a.timestamp) for a in ip_alerts if a.timestamp),
                default=datetime.now()
            )

            correlated.append(Alert(
                alert_type=rule["attack_type"],
                severity="CRITICAL",
                source_ip=ip,
                description=(
                    f"{rule['description']}\n"
                    f"    Contributing alerts: {', '.join(contributing)}"
                ),
                timestamp=earliest,
                evidence=all_evidence,
            ))

            # Only apply the most specific matching rule per IP
            break

    return correlated