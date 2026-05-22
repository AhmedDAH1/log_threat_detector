# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please **do not** open a public GitHub issue. Instead, report it privately:

- **Email**: open a private GitHub issue via the [Security Advisories](https://github.com/AhmedDAH1/log_threat_detector/security/advisories) tab, or contact me via [LinkedIn](https://www.linkedin.com/in/ahmed-dahdouh)
- I will acknowledge receipt within 72 hours
- We will discuss the issue privately and coordinate a fix before any public disclosure

## Scope

This is a learning project for a portfolio. It is **not intended for production use** without further hardening. The dashboard uses Flask's development server, the SQLite database is single-file, and there is no built-in authentication on the dashboard.

If you find a vulnerability in the detection logic, parsing code, or external API integrations (AbuseIPDB, SMTP), I'd genuinely like to know — these are the areas I want to learn most.

## Out of Scope

- The bundled sample logs (`logs/*.log`) contain deliberately malicious patterns for testing — IPs and user-agents in those files are not real vulnerabilities
- The intentional 5000-port AirPlay collision documented in `docker-compose.yml` — known macOS quirk, not a bug

## Credentials and Secrets

Secrets are loaded from environment variables (`ABUSEIPDB_API_KEY`, `SMTP_*`). The `.env` file is gitignored. If you find a committed credential in the repository history, please report it privately so it can be revoked.
