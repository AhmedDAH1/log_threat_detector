# Changelog

All notable changes to Log Threat Detector. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.3.0] - 2026-11-08

### Added
- **Analysis API** (`analysis_api.py`): `POST /api/analyze` takes one or more
  log files as text, detects whether each is an SSH, web server or firewall
  log, runs every detection and the correlation engine across all of them,
  and returns the alerts in the format `--forward` sends to SOAR-Lite.
  SOAR-Lite's "Analyze logs" page uses it. 5 MB per request.

## [1.2.0] - 2026-11-08

### Added
- `--forward URL` sends alerts to [SOAR-Lite](https://github.com/AhmedDAH1/soar-lite)
  as incidents, in batch and `--watch` mode, signed with HMAC-SHA256
  (`SOAR_WEBHOOK_SECRET`). Respects `--severity`; if SOAR-Lite is down,
  detection carries on.
- NetScan's User-Agent is on the suspicious User-Agent list.

### Fixed
- **Brute force against non-existent usernames went undetected.** sshd logs
  those attempts as `Failed password for invalid user <name>`, which the SSH
  parser skipped. That is how most brute-force attacks look, since they guess
  usernames.

### Security
- The dashboard escapes alert text before displaying it. Log lines are written
  by attackers (an SSH username, a User-Agent), so unescaped text could run
  script in the analyst's browser.
- Usernames from failed logins are reduced to printable characters, so they
  can't carry terminal escape codes into the CLI output.
- The dashboard's WebSocket accepts connections from its own page only, not
  from any website (`cors_allowed_origins="*"` was removed).
