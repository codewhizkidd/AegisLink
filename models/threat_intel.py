"""
Threat-intel pre-check layer: known-bad blocklists + domain age, checked
before the ML model runs. A hit here is authoritative (known blocklists
beat a heuristic model); a miss falls through to the ML score unchanged.
"""
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

GSB_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
GSB_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"

OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
URLHAUS_AUTH_KEY = os.environ.get("URLHAUS_AUTH_KEY", "").strip()

_openphish_cache = {"urls": set(), "fetched_at": None}
_OPENPHISH_TTL_SECONDS = 3600


def _get_domain(url):
    try:
        netloc = urlparse(url).netloc.lower().split(":")[0]
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""


def check_google_safe_browsing(url):
    if not GSB_API_KEY:
        return None
    body = {
        "client": {"clientId": "astro-phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(GSB_URL, json=body, timeout=5)
        resp.raise_for_status()
        return bool(resp.json().get("matches"))
    except Exception:
        return None


def _refresh_openphish_cache():
    now = datetime.now(timezone.utc)
    if (
        _openphish_cache["fetched_at"] is not None
        and (now - _openphish_cache["fetched_at"]).total_seconds() < _OPENPHISH_TTL_SECONDS
    ):
        return
    try:
        resp = requests.get(OPENPHISH_FEED_URL, timeout=8)
        resp.raise_for_status()
        _openphish_cache["urls"] = {line.strip() for line in resp.text.splitlines() if line.strip()}
        _openphish_cache["fetched_at"] = now
    except Exception:
        pass


def check_openphish(url):
    _refresh_openphish_cache()
    if not _openphish_cache["urls"]:
        return None
    domain = _get_domain(url)
    for entry in _openphish_cache["urls"]:
        if url.rstrip("/") == entry.rstrip("/") or (domain and domain == _get_domain(entry)):
            return True
    return False


def check_urlhaus(url):
    if not URLHAUS_AUTH_KEY:
        return None
    domain = _get_domain(url)
    if not domain:
        return None
    try:
        resp = requests.post(
            URLHAUS_API,
            data={"host": domain},
            headers={"Auth-Key": URLHAUS_AUTH_KEY},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") != "ok":
            return False
        # url_count alone is unreliable: large platforms (GitHub, Dropbox, etc.)
        # get abused to host malware payloads under user content paths, which
        # would falsely flag the whole domain. Only trust an explicit
        # blocklist listing (spamhaus_dbl / surbl) as domain-level evidence.
        blacklists = data.get("blacklists", {}) or {}
        return any(v not in (None, "not listed") for v in blacklists.values())
    except Exception:
        return None


def check_domain_age_days(domain):
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if resp.status_code != 200:
            return None
        data = resp.json()
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                registered = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - registered).days
    except Exception:
        return None
    return None


def evaluate(url):
    """
    Returns a dict:
      { "verdict": "phishing" | "clean" | "unknown", "reasons": [...], "domain_age_days": int|None }
    "phishing" verdict should short-circuit the ML model (blocklist override).
    "clean"/"unknown" fall through to the ML score.
    """
    reasons = []

    gsb_hit = check_google_safe_browsing(url)
    if gsb_hit:
        reasons.append("Listed in Google Safe Browsing")

    openphish_hit = check_openphish(url)
    if openphish_hit:
        reasons.append("Listed in OpenPhish feed")

    urlhaus_hit = check_urlhaus(url)
    if urlhaus_hit:
        reasons.append("Listed in URLhaus malware/phishing database")

    domain = _get_domain(url)
    age_days = check_domain_age_days(domain) if domain else None
    if age_days is not None and age_days < 30:
        reasons.append(f"Domain registered only {age_days} day(s) ago")

    if reasons and (gsb_hit or openphish_hit or urlhaus_hit):
        return {"verdict": "phishing", "reasons": reasons, "domain_age_days": age_days}

    if age_days is not None and age_days < 30:
        return {"verdict": "unknown", "reasons": reasons, "domain_age_days": age_days}

    # Domains registered 5+ years ago with zero blocklist hits are very
    # unlikely to be phishing (attackers rarely wait years before using a
    # domain), so trust-boost them rather than relying solely on the ML
    # model, which still misjudges some long-established sites with
    # neutral/ambiguous feature profiles (e.g. wikipedia.org).
    if age_days is not None and age_days >= 1825:
        return {"verdict": "trusted", "reasons": [], "domain_age_days": age_days}

    return {"verdict": "clean", "reasons": [], "domain_age_days": age_days}
