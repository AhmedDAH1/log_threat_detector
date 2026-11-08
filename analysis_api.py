# analysis_api.py
# An HTTP API for analysing log files on request, so another tool (SOAR-Lite's
# "Analyze logs" page) can hand over logs and get the detections back.
#
#   POST /api/analyze   {"logs": [{"name": "auth.log", "content": "...", "type": "auto"}]}
#   GET  /health
#
# Each log is parsed as SSH, Apache or firewall syslog ("auto" picks the parser
# that recognises the most lines), every detection runs, and the correlation
# engine runs across all logs in the request. Alerts come back in the same
# format the --forward option sends to SOAR-Lite, so SOAR-Lite treats an
# uploaded log exactly like a forwarded alert.
#
# Run: python3 analysis_api.py   (HOST and PORT from the environment, default 127.0.0.1:5001)

import os
import tempfile

from flask import Flask, jsonify, request

from detection.anomaly import detect_anomalies
from detection.brute_force import detect_brute_force
from detection.correlation import correlate_alerts
from detection.port_scan import detect_port_scan
from detection.user_agent import detect_suspicious_user_agents
from output.soar_forwarder import alert_payload
from parser.apache_parser import parse_apache_log
from parser.ssh_parser import parse_ssh_log
from parser.syslog_parser import parse_syslog

MAX_TOTAL_BYTES = 5 * 1024 * 1024   # per request; uploads are logs, not archives
MAX_LOGS = 20

PARSERS = {
    "ssh": (parse_ssh_log, [detect_brute_force]),
    "apache": (parse_apache_log, [detect_suspicious_user_agents, detect_anomalies]),
    "syslog": (parse_syslog, [detect_port_scan]),
}
TYPE_NAMES = {"ssh": "SSH auth log", "apache": "web server access log", "syslog": "firewall syslog"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_TOTAL_BYTES + 64 * 1024


def parse_text(text: str, log_type: str) -> tuple[str, list]:
    """Parse log text; with log_type "auto", use the parser that recognises the most lines."""
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        if log_type != "auto":
            return log_type, PARSERS[log_type][0](path)
        best_type, best_entries = None, []
        for name, (parse, _) in PARSERS.items():
            entries = parse(path)
            if len(entries) > len(best_entries):
                best_type, best_entries = name, entries
        return best_type, best_entries
    finally:
        os.unlink(path)


def analyze(logs: list[dict]) -> dict:
    """Run every detection on each log, then correlate across all of them."""
    summaries, alerts = [], []
    for log in logs:
        log_type, entries = parse_text(log["content"], log.get("type") or "auto")
        found = []
        if log_type:
            for detect in PARSERS[log_type][1]:
                found.extend(detect(entries))
        alerts.extend(found)
        summaries.append({
            "name": log.get("name", "log"),
            "type": log_type,
            "type_name": TYPE_NAMES.get(log_type, "not recognised"),
            "lines": log["content"].count("\n") + 1 if log["content"] else 0,
            "entries": len(entries),
            "alerts": len(found),
        })
    correlated = correlate_alerts(alerts) if alerts else []
    alerts.extend(correlated)
    return {"logs": summaries, "correlated": len(correlated), "alerts": [alert_payload(a) for a in alerts]}


def validate(data) -> tuple[list[dict] | None, str | None]:
    logs = data.get("logs") if isinstance(data, dict) else None
    if not isinstance(logs, list) or not logs:
        return None, 'Send {"logs": [{"name": ..., "content": ...}]}'
    if len(logs) > MAX_LOGS:
        return None, f"At most {MAX_LOGS} logs per request"
    total = 0
    for log in logs:
        if not isinstance(log, dict) or not isinstance(log.get("content"), str):
            return None, "Each log needs a text 'content'"
        if log.get("type", "auto") not in ("auto", *PARSERS):
            return None, f"Unknown log type {log.get('type')!r}; use auto, ssh, apache or syslog"
        total += len(log["content"].encode("utf-8"))
    if total > MAX_TOTAL_BYTES:
        return None, "Logs too large (5 MB per request)"
    return logs, None


@app.post("/api/analyze")
def api_analyze():
    logs, problem = validate(request.get_json(silent=True))
    if problem:
        return jsonify({"error": problem}), 400
    return jsonify(analyze(logs))


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5001")))
