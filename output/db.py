# output/db.py
# SQLite persistence layer for alerts.
# Stores all alerts with full metadata for historical analysis.

import sqlite3
import os
from colorama import Fore, Style, init
from detection.base import Alert

init(autoreset=True)

DB_FILE = os.path.join(os.path.dirname(__file__), "..", "alerts.db")


def init_db() -> None:
    """Create the alerts table if it doesn't exist."""
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp      TEXT,
                alert_type     TEXT,
                severity       TEXT,
                source_ip      TEXT,
                description    TEXT,
                evidence_count INTEGER,
                UNIQUE(timestamp, alert_type, source_ip)
            )
        """)
        conn.commit()


def save_alert(alert: Alert) -> None:
    """
    Saves an alert to the database.
    Silently skips duplicates (same timestamp + type + IP).
    """
    # Normalize timestamp — strip timezone info for consistent deduplication
    ts = str(alert.timestamp)
    if "+" in ts:
        ts = ts.split("+")[0].strip()

    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            INSERT OR IGNORE INTO alerts
            (timestamp, alert_type, severity, source_ip, description, evidence_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            ts,
            alert.alert_type,
            alert.severity,
            alert.source_ip,
            alert.description,
            len(alert.evidence),
        ))
        conn.commit()

def show_history(limit: int = 20) -> None:
    """Prints the most recent alerts from the database."""
    SEVERITY_COLORS = {
        "LOW":      Fore.CYAN,
        "MEDIUM":   Fore.YELLOW,
        "HIGH":     Fore.RED,
        "CRITICAL": Fore.RED + Style.BRIGHT,
    }

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("""
            SELECT timestamp, alert_type, severity, source_ip, description
            FROM alerts
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    if not rows:
        print(Fore.YELLOW + "\n  No alert history found. Run a detection first.\n")
        return

    print(Style.BRIGHT + f"\n📜 Alert History (last {len(rows)} alerts)\n")
    print(f"  {'SEVERITY':<10} {'TYPE':<30} {'SOURCE IP':<18} TIMESTAMP")
    print("  " + "─" * 80)

    for timestamp, alert_type, severity, source_ip, description in rows:
        color = SEVERITY_COLORS.get(severity, Fore.WHITE)
        print(
            color +
            f"  [{severity:<8}] {alert_type:<28} {source_ip:<18} {timestamp}"
        )

    print()