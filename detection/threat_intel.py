# detection/threat_intel.py
# Queries AbuseIPDB to check if a source IP is known malicious.
# Results are cached in memory to avoid redundant API calls.
import ssl
import certifi

# Fix macOS SSL certificate verification
ssl_context = ssl.create_default_context(cafile=certifi.where())
import urllib.request
import urllib.error
import json
import time
from config import CONFIG

# In-memory cache: ip -> {score, categories, cached_at}
_cache: dict[str, dict] = {}

ABUSE_CATEGORIES = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def lookup_ip(ip: str) -> dict | None:
    """
    Looks up an IP on AbuseIPDB.
    Returns a dict with score and categories, or None on failure.
    Uses in-memory cache to avoid redundant API calls.
    """
    cfg = CONFIG.get("threat_intel", {})
    if not cfg.get("enabled"):
        return None

    api_key = cfg.get("abuseipdb_api_key", "")
    if not api_key:
        return None

    # Check cache first
    ttl = cfg.get("cache_ttl_seconds", 3600)
    if ip in _cache:
        entry = _cache[ip]
        if time.time() - entry["cached_at"] < ttl:
            return entry

    try:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        req = urllib.request.Request(url)
        req.add_header("Key", api_key)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
            data = json.loads(response.read().decode())["data"]

        result = {
            "score":      data["abuseConfidenceScore"],
            "categories": [
                ABUSE_CATEGORIES.get(c, f"Category {c}")
                for c in (data.get("usageType") or "").split(", ")
                if c
            ],
            "country":    data.get("countryCode", "??"),
            "isp":        data.get("isp", "Unknown"),
            "total_reports": data.get("totalReports", 0),
            "cached_at":  time.time(),
        }

        _cache[ip] = result
        return result

    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
        print(f"  [THREAT INTEL] Lookup failed for {ip}: {e}")
        return None


def enrich_alert_with_intel(alert_source_ip: str) -> str | None:
    """
    Returns a formatted threat intel string for an IP,
    or None if the IP is clean or lookup failed.
    """
    cfg = CONFIG.get("threat_intel", {})
    min_score = cfg.get("min_abuse_score", 50)

    result = lookup_ip(alert_source_ip)
    if not result:
        return None

    score = result["score"]
    if score < min_score:
        return None

    cats = ", ".join(result["categories"]) if result["categories"] else "General abuse"
    return (
        f"🌐 Threat Intel: KNOWN MALICIOUS "
        f"(abuse score: {score}% | "
        f"reports: {result['total_reports']} | "
        f"country: {result['country']} | "
        f"ISP: {result['isp']})"
    )