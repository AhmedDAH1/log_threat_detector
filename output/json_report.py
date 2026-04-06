# output/json_report.py
# Serializes all alerts into a structured JSON report file.

import json
from datetime import datetime
from detection.base import Alert


def generate_report(alerts: list[Alert], output_path: str) -> None:
    """
    Writes all alerts to a JSON file.
    Each alert includes full metadata and evidence lines.
    """
    report = {
        "generated_at": datetime.now().isoformat(),
        "total_alerts": len(alerts),
        "alerts": [
            {
                "alert_type":  alert.alert_type,
                "severity":    alert.severity,
                "source_ip":   alert.source_ip,
                "description": alert.description,
                "timestamp":   alert.timestamp.isoformat() if alert.timestamp else None,
                "evidence":    alert.evidence,
            }
            for alert in alerts
        ]
    }

    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"  Report saved to: {output_path}")