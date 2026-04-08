# dashboard/server.py
# Flask + SocketIO web dashboard for log-threat-detector.
# Serves a live updating dashboard and streams alerts via WebSockets.

from flask import Flask, render_template
from flask_socketio import SocketIO
import threading
import json
from datetime import datetime
from detection.base import Alert

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "log-threat-detector-dashboard"
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory alert store
_alerts = []
_lock = threading.Lock()


def push_alert(alert: Alert) -> None:
    """Called from watch_mode when a new alert fires — pushes to all browser clients."""
    with _lock:
        entry = {
            "id":          len(_alerts) + 1,
            "alert_type":  alert.alert_type,
            "severity":    alert.severity,
            "source_ip":   alert.source_ip,
            "description": alert.description,
            "timestamp":   alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "—",
            "evidence":    len(alert.evidence),
        }
        _alerts.append(entry)

    socketio.emit("new_alert", entry)


def get_stats() -> dict:
    with _lock:
        total = len(_alerts)
        critical = sum(1 for a in _alerts if a["severity"] in ("HIGH", "CRITICAL"))
        medium = sum(1 for a in _alerts if a["severity"] == "MEDIUM")

        ip_counts = {}
        for a in _alerts:
            ip_counts[a["source_ip"]] = ip_counts.get(a["source_ip"], 0) + 1
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        return {
            "total": total,
            "critical": critical,
            "medium": medium,
            "top_ips": top_ips,
            "recent": list(reversed(_alerts[-20:])),
        }


@app.route("/")
def index():
    return render_template("index.html", stats=get_stats())


@app.route("/api/alerts")
def api_alerts():
    return json.dumps(get_stats())


@socketio.on("connect")
def on_connect():
    socketio.emit("init", get_stats())


def start_dashboard(host: str = "127.0.0.1", port: int = 5000) -> None:
    """Start the dashboard in a background thread."""
    thread = threading.Thread(
        target=lambda: socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True),
        daemon=True
    )
    thread.start()
    print(f"  🌐 Dashboard running at http://{host}:{port}")