# output/soar_forwarder.py
# Sends alerts to SOAR-Lite (https://github.com/AhmedDAH1/soar-lite), where each
# one becomes an incident: IOCs are extracted and enriched, playbooks run, and
# an analyst works the case.
#
# SOAR-Lite only accepts signed webhooks. Each request carries:
#   X-Webhook-Timestamp: <unix time>
#   X-Webhook-Signature: sha256=<HMAC-SHA256 of "<timestamp>." + body, keyed with the shared secret>
# The secret comes from the SOAR_WEBHOOK_SECRET environment variable and must
# match WEBHOOK_SECRET on the SOAR-Lite server.

import hashlib
import hmac
import json
import time
from urllib.parse import urlparse

import requests
from colorama import Fore

from detection.base import Alert

SIEM_WEBHOOK_PATH = "/api/webhooks/siem"
MAX_EVIDENCE_LINES = 20   # keep requests small; the full evidence stays in the local report
TIMEOUT_SECONDS = 10


def sign(body: bytes, secret: str, timestamp: int) -> str:
    """The X-Webhook-Signature value SOAR-Lite expects for this body."""
    message = f"{timestamp}.".encode() + body
    return "sha256=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def alert_payload(alert: Alert) -> dict:
    """An alert in SOAR-Lite's SIEM webhook format."""
    return {
        "search_name": f"{alert.alert_type} from {alert.source_ip}",
        "description": f"{alert.description} (source IP {alert.source_ip})",
        "severity": alert.severity.lower(),
        "result": {
            "detector": "log_threat_detector",
            "alert_type": alert.alert_type,
            "src_ip": alert.source_ip,
            "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
            "evidence": alert.evidence[:MAX_EVIDENCE_LINES],
            "evidence_total": len(alert.evidence),
        },
    }


class SoarForwarder:
    def __init__(self, base_url: str, secret: str):
        parsed = urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Not an http(s) URL: {base_url!r} (example: http://localhost:8000)")
        if not secret:
            raise ValueError("Set SOAR_WEBHOOK_SECRET to the WEBHOOK_SECRET configured in SOAR-Lite")
        self.url = base_url.rstrip("/") + SIEM_WEBHOOK_PATH
        self.secret = secret

    def send(self, alert: Alert) -> bool:
        """Forward one alert. Failures are reported, never raised: detection must keep running."""
        body = json.dumps(alert_payload(alert)).encode()
        timestamp = int(time.time())
        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Timestamp": str(timestamp),
            "X-Webhook-Signature": sign(body, self.secret, timestamp),
        }
        try:
            response = requests.post(self.url, data=body, headers=headers, timeout=TIMEOUT_SECONDS)
        except requests.RequestException as e:
            print(Fore.YELLOW + f"  [WARN] Could not reach SOAR-Lite at {self.url}: {e.__class__.__name__}")
            return False
        if response.status_code != 201:
            print(Fore.YELLOW + f"  [WARN] SOAR-Lite refused the alert: HTTP {response.status_code} {response.text[:200]}")
            return False
        incident = response.json().get("incident_id")
        print(Fore.CYAN + f"  ↗ Sent to SOAR-Lite: incident #{incident} ({alert.alert_type} from {alert.source_ip})")
        return True

    def send_all(self, alerts: list[Alert]) -> int:
        return sum(self.send(alert) for alert in alerts)
