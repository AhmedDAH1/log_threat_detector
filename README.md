# 🔍 Log Threat Detector

> **🚀 [Live Demo →](https://log-threat-detector.onrender.com)** &nbsp;·&nbsp; Try the dashboard with pre-loaded real-world attack data.
> *Hosted on Render free tier — first load may take ~30 seconds while the container wakes.*

[![Live Demo](https://img.shields.io/badge/Live_Demo-Online-success?style=flat-square)](https://log-threat-detector.onrender.com)
![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Docker](https://img.shields.io/badge/Docker-ready-blue?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Tests](https://github.com/AhmedDAH1/log_threat_detector/actions/workflows/tests.yml/badge.svg)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red?style=flat-square)

A SIEM-style threat detection CLI that parses SSH, Apache, and syslog files to detect brute-force attacks, port scans, and suspicious activity — with real-time monitoring, email alerting, a correlation engine that connects multi-vector attacks, and live threat intelligence via AbuseIPDB.

---

## Why I Built This

I'm a Software Engineering student specializing in cybersecurity, working toward a SOC analyst / detection engineer role. Reading about how SIEMs like Splunk and Elastic correlate alerts across log sources, I wanted to understand the mechanics myself — not by reading documentation, but by building one. This project is the result: a working multi-source log parser, sliding-window detection engine, and correlation layer that fires `CRITICAL` alerts when the same IP triggers reconnaissance patterns across different log types. The goal was to internalize how detection engineering actually works at the code level.

---

## Architecture

![Architecture](assets/architecture.svg)

> Log files → Parsers → Detection engines → Correlation engine → Threat intelligence → Alert output + JSON report

---

## Demo

![Demo](assets/demo.gif)

---

## Web Dashboard

![Dashboard Dark](assets/dashboard_dark.png)
![Dashboard Light](assets/dashboard_light.png)

Try the [live demo](https://log-threat-detector.onrender.com), or run it locally with Docker (see Installation below).

---

## Features

| Detection | Log Source | Severity |
|---|---|---|
| Brute force login attempts | SSH logs | HIGH |
| Port scan detection | Syslog (UFW/iptables) | HIGH |
| Suspicious user agents | Apache logs | MEDIUM |
| Anomaly / high request rate | Apache logs | MEDIUM |
| Multi-vector correlation engine | All sources | CRITICAL |
| AbuseIPDB threat intelligence | All alerts | — |
| Real-time monitoring (`--watch`) | Any supported log | — |
| Email alerting | Watch mode (HIGH/CRITICAL) | — |
| Alert persistence | SQLite database | — |

---

## How the Correlation Engine Works

Most log parsers fire independent alerts. This tool goes further — it groups alerts by source IP across all log sources and detects coordinated attack patterns:

| Pattern | Alert Type | Triggers When |
|---|---|---|
| Port scan + suspicious user agent | `RECONNAISSANCE` | Same IP probes ports and uses attack tools |
| Brute force + port scan | `COORDINATED_ATTACK` | Same IP scans and attempts login |
| Brute force + suspicious user agent | `TARGETED_ATTACK` | Same IP uses tools and forces login |
| All three | `FULL_COMPROMISE_ATTEMPT` | Same IP triggers every attack vector |

When a pattern is matched, all contributing alerts are merged into a single `CRITICAL` alert with combined evidence — exactly how commercial SIEM tools like Splunk operate.

---

## Threat Intelligence

Every alert is automatically enriched with live threat intelligence from AbuseIPDB. Known malicious IPs are flagged instantly:

```
[HIGH] BRUTE_FORCE — 80.82.77.33
  6 failed login attempts in 60s targeting user(s): root
  🌐 Threat Intel: KNOWN MALICIOUS (abuse score: 100% | reports: 8209 | country: NL | ISP: FiberXpress BV)
```

> Get a free API key at https://www.abuseipdb.com — 1000 lookups/day on the free tier. Set it via the `ABUSEIPDB_API_KEY` environment variable. Without a key, threat intel is silently skipped and detection still works normally.

---

## Installation

### Option 1 — Docker (recommended)

```bash
git clone https://github.com/AhmedDAH1/log_threat_detector.git
cd log_threat_detector

# Set up your API key (optional — threat intel works without it, just less useful)
cp .env.example .env
# Edit .env and add your AbuseIPDB key

# Launch the full demo with dashboard
docker compose up
```

Open http://localhost:5050 in your browser. The dashboard loads with 11 pre-detected alerts including a `CRITICAL` correlation-engine hit.

### Option 2 — Local Python

```bash
git clone https://github.com/AhmedDAH1/log_threat_detector.git
cd log_threat_detector
pip install -r requirements.txt

# Optional: set your AbuseIPDB key
export ABUSEIPDB_API_KEY=your_key_here

# Run all detections on bundled sample logs
python3 main.py --all

# Or launch the dashboard with demo data pre-loaded
python3 main.py --demo
```

---

## Usage

```bash
# Run all detections on all default log files
python3 main.py --all

# Show only HIGH and CRITICAL alerts
python3 main.py --all --severity HIGH

# Run only brute force detection on a specific SSH log
python3 main.py --ssh logs/ssh.log --brute-force

# Run user agent and anomaly detection on Apache logs
python3 main.py --apache logs/apache.log --user-agent --anomaly

# Run port scan detection and save a custom report
python3 main.py --syslog logs/syslog.log --port-scan --report output/report.json

# Watch a log file in real time for live threat detection
python3 main.py --watch logs/ssh.log

# Run the full demo with dashboard (used by the live demo deployment)
python3 main.py --demo

# View alert history from the database
python3 main.py --history
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
  --dashboard       Launch web dashboard at http://localhost:5000
  --demo            Run all detections on sample logs, then keep dashboard alive

History:
  --history         Show the last 20 alerts from the database

Output options:
  --severity LEVEL  Minimum severity: LOW | MEDIUM | HIGH | CRITICAL (default: LOW)
  --report [FILE]   Save JSON report (default: output/report.json)
```

---

## Alert Persistence (SQLite)

All detected alerts are automatically saved to a local SQLite database (`alerts.db`). This allows historical analysis and threat tracking across multiple runs.

```bash
python3 main.py --history
```

---

## Email Alerting

When running in `--watch` mode, the tool sends email notifications for HIGH and CRITICAL alerts. Configure via environment variables:

```bash
SMTP_SENDER_EMAIL=your_gmail@gmail.com
SMTP_SENDER_PASSWORD=your_app_password
SMTP_RECIPIENT_EMAIL=alerts@yourdomain.com
```

> Use a Gmail App Password — not your regular password. Generate one at https://myaccount.google.com/apppasswords.

---

## Project Structure

```
log_threat_detector/
├── main.py                    # CLI entry point
├── config.py                  # Central thresholds (secrets via env vars)
├── Dockerfile                 # Production container (non-root, slim base)
├── docker-compose.yml         # One-command dashboard launch
├── .env.example               # Template for environment variables
├── Makefile                   # Shortcuts for common commands
├── parser/
│   ├── base.py                # Shared LogEntry data model
│   ├── ssh_parser.py          # OpenSSH log parser
│   ├── apache_parser.py       # Apache Combined Log Format parser
│   └── syslog_parser.py       # UFW/iptables syslog parser
├── detection/
│   ├── base.py                # Shared Alert data model
│   ├── brute_force.py         # Brute force detection (sliding window)
│   ├── port_scan.py           # Port scan detection (sliding window)
│   ├── user_agent.py          # Suspicious user agent detection
│   ├── anomaly.py             # High request rate anomaly detection
│   ├── correlation.py         # Multi-vector attack correlation engine
│   ├── watch_mode.py          # Real-time log tailing engine
│   └── threat_intel.py        # AbuseIPDB threat intelligence integration
├── dashboard/                 # Flask + SocketIO web dashboard
├── output/
│   ├── alert_output.py        # Colored terminal output with severity filter
│   ├── json_report.py         # JSON report generator
│   ├── email_alert.py         # Email notifications for HIGH/CRITICAL alerts
│   └── db.py                  # SQLite alert persistence and history
├── logs/                      # Sample log files
├── tests/                     # Unit tests (14 tests)
└── requirements.txt
```

---

## Sample Output

```
🔍 Log Threat Detector — Starting Analysis

── SSH: logs/ssh.log (28 entries) ───────────────
  [HIGH] BRUTE_FORCE — 80.82.77.33
    6 failed login attempts in 60s targeting user(s): root
    First seen : 2026-12-10 08:00:01
    Evidence   : 6 log line(s)
    🌐 Threat Intel: KNOWN MALICIOUS (abuse score: 100% | reports: 8209 | country: NL | ISP: FiberXpress BV)

── Apache: logs/apache.log (11 entries) ─────────
  [MEDIUM] SUSPICIOUS_USER_AGENT — 45.33.32.156
    Malicious tool detected in User-Agent: 'nikto'

── Syslog: logs/syslog.log (13 entries) ─────────
  [HIGH] PORT_SCAN — 45.33.32.156
    11 unique ports probed in 10s: [22, 25, 80, 443, 3306, ...]

── Correlation Engine ────────────────────────────
  [CRITICAL] RECONNAISSANCE — 45.33.32.156
    Same IP performed port scanning and used a known attack tool.
    Contributing alerts: SUSPICIOUS_USER_AGENT (MEDIUM), PORT_SCAN (HIGH)
    First seen : 2026-12-10 07:10:00
    Evidence   : 12 log line(s)

========== SUMMARY ==========
  Total alerts : 9
  High/Critical: 6
  Medium       : 3
  Low          : 0
==============================
```

---

## Skills Demonstrated

This project maps directly to core SOC analyst and detection engineering competencies:

| Skill | Where in this project |
|---|---|
| Log parsing across multiple formats | `parser/` — SSH, Apache Combined, syslog |
| Detection engineering | `detection/` — sliding-window brute force, port scan, user agent |
| Alert correlation across data sources | `detection/correlation.py` — multi-vector pattern matching |
| Threat intelligence enrichment | `detection/threat_intel.py` — AbuseIPDB integration with caching |
| Secure secret management | `os.environ.get()` pattern, `.env` gitignored, `.env.example` committed |
| Containerization | Dockerfile (non-root, slim, layer-cached) + docker-compose |
| Cloud deployment | Live on Render with Docker runtime |
| Real-time data streaming | Flask + SocketIO dashboard with WebSocket alert push |
| Database persistence | SQLite with deduplication keys |
| CI/CD | GitHub Actions running 14 unit tests on every push |
| Reporting | JSON output for downstream tooling |

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
    "anomaly": {
        "request_rate_per_minute": 100,
    },
    "threat_intel": {
        "enabled": True,
        "abuseipdb_api_key": os.environ.get("ABUSEIPDB_API_KEY", ""),
        "min_abuse_score": 50,
        "cache_ttl_seconds": 3600,
    },
}
```

---

## Tech Stack

- **Language**: Python 3.10+
- **Web**: Flask + Flask-SocketIO for the real-time dashboard
- **Persistence**: SQLite for alert history
- **Containerization**: Docker + docker-compose
- **Deployment**: Render (Docker runtime, free tier)
- **External API**: AbuseIPDB for live threat intelligence
- **CI**: GitHub Actions — 14 tests run automatically on every push
- **Architecture**: Modular — parsers, detectors, and output fully decoupled

---

## Makefile

```bash
make run      # run all detections on default log files
make test     # run all 14 unit tests
make watch    # start live monitoring on ssh log
make clean    # remove cache and generated reports
```

---

## Author

**Ahmed Dahdouh**
Software Engineering Student · Cybersecurity Enthusiast

[![GitHub](https://img.shields.io/badge/GitHub-AhmedDAH1-black?style=flat-square&logo=github)](https://github.com/AhmedDAH1)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ahmed_Dahdouh-0A66C2?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/ahmed-dahdouh)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-AhmedDAH1-212C42?style=flat-square&logo=tryhackme)](https://tryhackme.com/p/AhmedDAH1)

---

## License

MIT — see [LICENSE](LICENSE)
