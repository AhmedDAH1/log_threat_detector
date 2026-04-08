# output/email_alert.py
# Sends email notifications when HIGH or CRITICAL alerts fire in watch mode.
# Uses Python's built-in smtplib — no extra dependencies required.

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from detection.base import Alert


def send_email_alert(
    alert: Alert,
    sender_email: str,
    sender_password: str,
    recipient_email: str,
    smtp_host: str = "smtp.gmail.com",
    smtp_port: int = 587,
) -> bool:
    """
    Sends an email notification for a single alert.
    Returns True on success, False on failure.
    Only sends for HIGH and CRITICAL alerts.
    """
    if alert.severity not in ("HIGH", "CRITICAL"):
        return False

    subject = f"[{alert.severity}] {alert.alert_type} detected — {alert.source_ip}"

    body = f"""
Log Threat Detector — Security Alert
=====================================
Type     : {alert.alert_type}
Severity : {alert.severity}
Source IP: {alert.source_ip}
Time     : {alert.timestamp}

Description:
{alert.description}

Evidence ({len(alert.evidence)} line(s)):
{chr(10).join(alert.evidence[:5])}
{"..." if len(alert.evidence) > 5 else ""}
=====================================
This alert was generated automatically by log-threat-detector.
"""

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = recipient_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
        return True
    except Exception as e:
        print(f"  [EMAIL ERROR] Failed to send alert: {e}")
        return False