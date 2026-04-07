# output/alert_output.py
# Prints alerts to the terminal with color-coded severity levels.

from colorama import init, Fore, Style
from detection.base import Alert

init(autoreset=True)

SEVERITY_COLORS = {
    "LOW":      Fore.CYAN,
    "MEDIUM":   Fore.YELLOW,
    "HIGH":     Fore.RED,
    "CRITICAL": Fore.RED + Style.BRIGHT,
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def filter_by_severity(alerts: list[Alert], min_severity: str) -> list[Alert]:
    """Filter alerts to only include those at or above the given severity."""
    min_rank = SEVERITY_RANK.get(min_severity.upper(), 1)
    return [a for a in alerts if SEVERITY_RANK.get(a.severity, 0) >= min_rank]


def print_alerts(alerts: list[Alert], min_severity: str = "LOW") -> None:
    filtered = filter_by_severity(alerts, min_severity)

    if not filtered:
        if min_severity == "LOW":
            print(Fore.GREEN + "  No threats detected.")
        return

    for alert in filtered:
        color = SEVERITY_COLORS.get(alert.severity, Fore.WHITE)
        print(color + f"  [{alert.severity}] {alert.alert_type} — {alert.source_ip}")
        print(f"    {alert.description}")
        print(Style.DIM + f"    First seen : {alert.timestamp}")
        print(Style.DIM + f"    Evidence   : {len(alert.evidence)} log line(s)")
        print()


def print_summary(all_alerts: list[Alert], min_severity: str = "LOW") -> None:
    filtered = filter_by_severity(all_alerts, min_severity)
    total = len(filtered)
    high  = sum(1 for a in filtered if a.severity in ("HIGH", "CRITICAL"))
    med   = sum(1 for a in filtered if a.severity == "MEDIUM")
    low   = sum(1 for a in filtered if a.severity == "LOW")

    print(Style.BRIGHT + "\n========== SUMMARY ==========")
    print(f"  Total alerts : {total}")
    print(Fore.RED    + f"  High/Critical: {high}")
    print(Fore.YELLOW + f"  Medium       : {med}")
    print(Fore.CYAN   + f"  Low          : {low}")
    if min_severity != "LOW":
        print(Style.DIM + f"  Filter       : {min_severity}+")
    print(Style.BRIGHT + "==============================\n")