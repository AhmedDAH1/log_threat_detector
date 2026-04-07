# 🔍 Log Threat Detector

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://github.com/AhmedDAH1/log_threat_detector/actions/workflows/tests.yml/badge.svg)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)

## Architecture

![Architecture](assets/architecture.svg)

> Log files → Parsers → Detection engines → Alert output + JSON report

A SIEM-style log analysis tool that ingests syslog, Apache, and SSH logs and detects suspicious activity using rule-based heuristics.

Built as a portfolio-grade cybersecurity project in Python.
---
## Demo

![Demo](assets/demo.gif)
## Features

| Detection | Log Source | Severity |
|---|---|---|
| Brute force login attempts | SSH logs | HIGH |
| Port scan detection | Syslog (UFW/iptables) | HIGH |
| Suspicious user agents | Apache logs | MEDIUM |
| Anomaly / high request rate | Apache logs | MEDIUM |

---

## Project Structure
```
log_threat_detector/
├── main.py                  # CLI entry point
├── config.py                # Central thresholds and settings
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
│   └── anomaly.py           # High request rate anomaly detection
├── output/
│   ├── alert_output.py      # Colored terminal output
│   └── json_report.py       # JSON report generator
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

# Run only brute force detection on a specific SSH log
python3 main.py --ssh logs/ssh.log --brute-force

# Run user agent and anomaly detection on Apache logs
python3 main.py --apache logs/apache.log --user-agent --anomaly

# Run port scan detection and save a custom report
python3 main.py --syslog logs/syslog.log --port-scan --report output/report.json

# Watch a log file in real time for live threat detection
python3 main.py --watch logs/ssh.log
```

### All CLI options
```
Log file inputs:
  --ssh FILE       Path to SSH log file
  --apache FILE    Path to Apache log file
  --syslog FILE    Path to syslog file

Detection modules:
  --brute-force    Detect brute force login attempts
  --user-agent     Detect suspicious user agents
  --anomaly        Detect high request rate anomalies
  --port-scan      Detect port scan attempts
  --all            Run all detections on all default log files
  --watch FILE     Tail a log file in real time and detect threats as they appear

Output options:
  --report [FILE]  Save JSON report (default: output/report.json)
```

---

## Sample Output
```
🔍 Log Threat Detector — Starting Analysis

── SSH: logs/ssh.log (8 entries) ───────────────
  [HIGH] BRUTE_FORCE — 192.168.1.105
    6 failed login attempts in 60s targeting user(s): root, admin
    First seen : 2026-12-10 06:55:48
    Evidence   : 6 log line(s)

── Apache: logs/apache.log (10 entries) ────────
  [MEDIUM] SUSPICIOUS_USER_AGENT — 203.0.113.55
    Malicious tool detected in User-Agent: 'sqlmap'

── Syslog: logs/syslog.log (13 entries) ────────
  [HIGH] PORT_SCAN — 45.33.32.156
    11 unique ports probed in 10s: [22, 25, 80, ...]

========== SUMMARY ==========
  Total alerts : 4
  High/Critical: 2
  Medium       : 2
  Low          : 0
==============================
```

---

## Configuration

All thresholds are defined in `config.py` — no need to touch detection logic:
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
    ...
}
```

---

## Tech Stack

- **Language**: Python 3.10+
- **Libraries**: `colorama` for terminal output
- **Architecture**: Modular — parsers, detectors, and output are fully decoupled

---

## Author

Ahmed Dahdouh — [GitHub](https://github.com/AhmedDAH1)
