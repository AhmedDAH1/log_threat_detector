# main.py
# CLI entry point for log-threat-detector.
# Usage: python3 main.py --help

import argparse
import sys
from colorama import Fore, Style, init
from detection.correlation import correlate_alerts

from parser.ssh_parser import parse_ssh_log
from parser.apache_parser import parse_apache_log
from parser.syslog_parser import parse_syslog

from detection.brute_force import detect_brute_force
from detection.user_agent import detect_suspicious_user_agents
from detection.anomaly import detect_anomalies
from detection.port_scan import detect_port_scan
from detection.watch_mode import watch

from output.alert_output import print_alerts, print_summary
from output.json_report import generate_report

from config import CONFIG

init(autoreset=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-threat-detector",
        description="SIEM-style log parser and threat detector.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 main.py --all\n"
            "  python3 main.py --all --severity HIGH\n"
            "  python3 main.py --ssh logs/ssh.log --brute-force\n"
            "  python3 main.py --apache logs/apache.log --user-agent --anomaly\n"
            "  python3 main.py --syslog logs/syslog.log --port-scan --report out.json\n"
            "  python3 main.py --watch logs/ssh.log\n"
        )
    )

    # Log file inputs
    inputs = parser.add_argument_group("Log file inputs")
    inputs.add_argument("--ssh",    metavar="FILE", help="Path to SSH log file")
    inputs.add_argument("--apache", metavar="FILE", help="Path to Apache log file")
    inputs.add_argument("--syslog", metavar="FILE", help="Path to syslog file")

    # Detection modules
    detections = parser.add_argument_group("Detection modules")
    detections.add_argument("--brute-force", action="store_true", help="Detect brute force login attempts")
    detections.add_argument("--user-agent",  action="store_true", help="Detect suspicious user agents")
    detections.add_argument("--anomaly",     action="store_true", help="Detect high request rate anomalies")
    detections.add_argument("--port-scan",   action="store_true", help="Detect port scan attempts")
    detections.add_argument("--all",         action="store_true", help="Run all detections on all default log files")

    # Live monitoring
    watch_group = parser.add_argument_group("Live monitoring")
    watch_group.add_argument(
        "--watch",
        metavar="FILE",
        help="Tail a log file in real time and detect threats as they appear"
    )

    # Output options
    outputs = parser.add_argument_group("Output options")
    outputs.add_argument(
        "--severity",
        metavar="LEVEL",
        default="LOW",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        help="Minimum severity to display: LOW | MEDIUM | HIGH | CRITICAL (default: LOW)"
    )
    outputs.add_argument(
        "--report",
        metavar="FILE",
        nargs="?",
        const=CONFIG["output"]["report_path"],
        help=f"Save JSON report (default path: {CONFIG['output']['report_path']})"
    )

    return parser


def run(args: argparse.Namespace) -> None:

    # Watch mode — takes priority over everything else
    if args.watch:
        watch(args.watch)
        return

    all_alerts = []

    # --all flag: use default config paths and all detections
    if args.all:
        args.ssh         = args.ssh    or CONFIG["log_paths"]["ssh"]
        args.apache      = args.apache or CONFIG["log_paths"]["apache"]
        args.syslog      = args.syslog or CONFIG["log_paths"]["syslog"]
        args.brute_force = True
        args.user_agent  = True
        args.anomaly     = True
        args.port_scan   = True
        args.report      = args.report or CONFIG["output"]["report_path"]

    print(Style.BRIGHT + "\n🔍 Log Threat Detector — Starting Analysis\n")

    # SSH detections
    if args.ssh:
        try:
            ssh_entries = parse_ssh_log(args.ssh)
            print(f"── SSH: {args.ssh} ({len(ssh_entries)} entries) ───────────────")
            if args.brute_force:
                alerts = detect_brute_force(ssh_entries)
                print_alerts(alerts, min_severity=args.severity)
                all_alerts.extend(alerts)
        except FileNotFoundError:
            print(Fore.RED + f"  [ERROR] SSH log not found: {args.ssh}")

    # Apache detections
    if args.apache:
        try:
            apache_entries = parse_apache_log(args.apache)
            print(f"── Apache: {args.apache} ({len(apache_entries)} entries) ──────────────")
            if args.user_agent:
                alerts = detect_suspicious_user_agents(apache_entries)
                print_alerts(alerts, min_severity=args.severity)
                all_alerts.extend(alerts)
            if args.anomaly:
                alerts = detect_anomalies(apache_entries)
                print_alerts(alerts, min_severity=args.severity)
                all_alerts.extend(alerts)
        except FileNotFoundError:
            print(Fore.RED + f"  [ERROR] Apache log not found: {args.apache}")

    # Syslog detections
    if args.syslog:
        try:
            syslog_entries = parse_syslog(args.syslog)
            print(f"── Syslog: {args.syslog} ({len(syslog_entries)} entries) ──────────────")
            if args.port_scan:
                alerts = detect_port_scan(syslog_entries)
                print_alerts(alerts, min_severity=args.severity)
                all_alerts.extend(alerts)
        except FileNotFoundError:
            print(Fore.RED + f"  [ERROR] Syslog not found: {args.syslog}")

    if not all_alerts and not any([args.ssh, args.apache, args.syslog]):
        print(Fore.YELLOW + "  No log files specified. Use --help to see usage.")
        sys.exit(0)

    # Correlation engine — run after all individual detections
    if all_alerts:
        print("── Correlation Engine ────────────────────")
        correlated = correlate_alerts(all_alerts)
        if correlated:
            print_alerts(correlated, min_severity=args.severity)
            all_alerts.extend(correlated)
        else:
            print(Fore.GREEN + "  No correlated attack patterns detected.\n")

    print_summary(all_alerts, min_severity=args.severity)

    if args.report:
        generate_report(all_alerts, args.report)


if __name__ == "__main__":
    arg_parser = build_parser()
    args = arg_parser.parse_args()
    run(args)