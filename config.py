# config.py
# Central configuration for log-threat-detector
# Adjust thresholds here without touching detection logic

CONFIG = {
    "email": {
    "enabled": False,
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "",
    "sender_password": "",
    "recipient_email": "",
},
    "brute_force": {
        "max_failed_attempts": 5,       # failed logins before alert
        "time_window_seconds": 60,      # within this time window
    },
    "port_scan": {
        "max_ports": 10,                # unique ports from one IP
        "time_window_seconds": 10,
    },
    "suspicious_user_agents": [
        "sqlmap", "nikto", "nmap", "masscan",
        "zgrab", "dirbuster", "curl", "python-requests"
    ],
    "anomaly": {
        "request_rate_per_minute": 100, # requests/min before flagging
    },
    "log_paths": {
        "syslog":  "logs/syslog.log",
        "apache":  "logs/apache.log",
        "ssh":     "logs/ssh.log",
    },
    "output": {
        "report_path": "output/report.json",
        "alert_level": "WARNING",       # INFO | WARNING | CRITICAL
    }
    
}