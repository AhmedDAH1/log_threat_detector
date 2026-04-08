# 🔍 Log Threat Detector

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://github.com/AhmedDAH1/log_threat_detector/actions/workflows/tests.yml/badge.svg)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)

A lightweight SIEM-style threat detection tool that analyzes SSH, Apache, and syslog files to detect brute-force attacks, port scans, and suspicious activity — with real-time monitoring and email alerting.

---

## Architecture

![Architecture](assets/architecture.svg)

> Log files → Parsers → Detection engines → Alert output + JSON report

---

## Demo

![Demo](assets/demo.gif)

---

## Features

| Detection | Log Source | Severity |
|---|---|---|
| Brute force login attempts | SSH logs | HIGH |
| Port scan detection | Syslog (UFW/iptables) | HIGH |
| Suspicious user agents | Apache logs | MEDIUM |
| Anomaly / high request rate | Apache logs | MEDIUM |
| Real-time monitoring (`--watch`) | Any supported log | — |
| Email alerting on HIGH/CRITICAL | Watch mode | HIGH |

---

## Project Structure

```
log_threat_detector/
├── main.py                  # CLI entry point
├── config.py                # Central thresholds and settings
├── Makefile                 # Shortcuts for common commands
├── parser/
│   ├── base.py              # Shared LogEntry data model
│   ├── ssh_parser.py        # OpenSSH log parser
│   ├── apache_parser.py     # Apache Combined Log Format parser
│   └── syslog_parser.py     # UFW/iptables syslog parser
├── detection/
│   ├── base.py              # Shared Alert data model
│   ├── brute_force.py       # Brute force detection
│   ├── port_scan.py         # Port scan detection
│   ├── user_agent.py        # Suspicious user agent detection
│   ├── anomaly.py           # High request rate anomaly detection
│   └── watch_mode.py        # Real-time log tailing engine
├── output/
│   ├── alert_output.py      # Colored terminal output
│   ├── json_report.py       # JSON report generator
│   └── email_alert.py       # Email notification on HIGH/CRITICAL alerts
├── logs/                    # Sample log files
├── tests/                   # Unit tests
└── requirements.txt
```

---

## Installation

```bash
git clone https://github.com/AhmedDAH1/log_threat_detector.git
cd log_threat_detector
pip install -r requirements.txt
```

---

## Usage

```bash
# Run all detections on all default log files
python3 main.py --all

# Show only HIGH and above
python3 main.py --all --severity HIGH

# Run only brute force detection on a specific SSH log
python3 main.py --ssh logs/ssh.log --brute-force

# Run user agent and anomaly detection on Apache logs
python3 main.py --apache logs/apache.log --user-agent --anomaly

# Run port scan detection and save a custom report
python3 main.py --syslog logs/syslog.log --port-scan --report output/report.json

# Watch a log file in real time for live threat detection
python3 main.py --watch logs/ssh.log
```

---

## CLI Options

```
Log file inputs:
  --ssh FILE        Path to SSH log file
  --apache FILE     Path to Apache log file
  --syslog FILE     Path to syslog file

Detection modules:
  --brute-force     Detect brute force login attempts
  --user-agent      Detect suspicious user agents
  --anomaly         Detect high request rate anomalies
  --port-scan       Detect port scan attempts
  --all             Run all detections on all default log files

Live monitoring:
  --watch FILE      Tail a log file in real time and detect threats as they appear

Output options:
  --severity LEVEL  Minimum severity: LOW | MEDIUM | HIGH | CRITICAL (default: LOW)
  --report [FILE]   Save JSON report (default: output/report.json)
```

---

## Makefile

```bash
make run      # run all detections on default log files
make test     # run all 14 unit tests
make watch    # start live monitoring on ssh log
make clean    # remove cache and generated reports
```

---

## Email Alerting

When running in `--watch` mode, the tool can send email notifications for HIGH and CRITICAL alerts. Configure in `config.py`:

```python
"email": {
    "enabled": True,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_gmail@gmail.com",
    "sender_password": "your_app_password",
    "recipient_email": "alerts@yourdomain.com",
}
```

> **Note:** Use a Gmail App Password — not your regular password. Generate one at https://myaccount.google.com/apppasswords. Never commit real credentials to the repo.

---

## Sample Output

```
🔍 Log Threat Detector — Starting Analysis

── SSH: logs/ssh.log (15 entries) ───────────────
  [HIGH] BRUTE_FORCE — 192.168.1.105
    7 failed login attempts in 60s targeting user(s): root, admin
    First seen : 2026-12-10 06:55:48
    Evidence   : 7 log line(s)

── Apache: logs/apache.log (10 entries) ─────────
  [MEDIUM] SUSPICIOUS_USER_AGENT — 203.0.113.55
    Malicious tool detected in User-Agent: 'sqlmap'

── Syslog: logs/syslog.log (13 entries) ─────────
  [HIGH] PORT_SCAN — 45.33.32.156
    11 unique ports probed in 10s: [22, 25, 80, 443, 3306, ...]

========== SUMMARY ==========
  Total alerts : 5
  High/Critical: 3
  Medium       : 2
  Low          : 0
==============================
```

---

## Configuration

All thresholds live in `config.py` — adjust without touching detection logic:

```python
CONFIG = {
    "brute_force": {
        "max_failed_attempts": 5,
        "time_window_seconds": 60,
    },
    "port_scan": {
        "max_ports": 10,
        "time_window_seconds": 10,
    },
}
```

---

## Tech Stack

- **Language**: Python 3.10+
- **Libraries**: `colorama` for terminal output
- **Architecture**: Modular — parsers, detectors, and output are fully decoupled
- **CI**: GitHub Actions — tests run automatically on every push

---

## Author

Ahmed Dahdouh — [GitHub](https://github.com/AhmedDAH1)
