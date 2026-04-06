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


def print_alerts(alerts: list[Alert]) -> None:
    if not alerts:
        print(Fore.GREEN + "  No threats detected.")
        return

    for alert in alerts:
        color = SEVERITY_COLORS.get(alert.severity, Fore.WHITE)
        print(color + f"  [{alert.severity}] {alert.alert_type} — {alert.source_ip}")
        print(f"    {alert.description}")
        print(Style.DIM + f"    First seen : {alert.timestamp}")
        print(Style.DIM + f"    Evidence   : {len(alert.evidence)} log line(s)")
        print()


def print_summary(all_alerts: list[Alert]) -> None:
    total = len(all_alerts)
    high  = sum(1 for a in all_alerts if a.severity in ("HIGH", "CRITICAL"))
    med   = sum(1 for a in all_alerts if a.severity == "MEDIUM")
    low   = sum(1 for a in all_alerts if a.severity == "LOW")

    print(Style.BRIGHT + "\n========== SUMMARY ==========")
    print(f"  Total alerts : {total}")
    print(Fore.RED    + f"  High/Critical: {high}")
    print(Fore.YELLOW + f"  Medium       : {med}")
    print(Fore.CYAN   + f"  Low          : {low}")
    print(Style.BRIGHT + "==============================\n")