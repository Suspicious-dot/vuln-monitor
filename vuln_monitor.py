#!/usr/bin/env python3
"""
Vulnerability Monitor — Slack Alerting Bot
Monitors: NVD/CVE, Exploit-DB, GitHub Security Advisories, Full Disclosure
Posts new vulnerabilities to Slack with rich formatting.
"""

import os
import json
import hashlib
import logging
import requests
import feedparser
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
STATE_FILE = Path("seen_vulns.json")
CHECK_HOURS_BACK = 1  # how far back to look each run (in hours)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ── State Management (deduplication) ─────────────────────────────────────────
def load_seen() -> set:
    if STATE_FILE.exists():
        try:
            return set(json.loads(STATE_FILE.read_text()))
        except Exception:
            return set()
    return set()

def save_seen(seen: set):
    # Keep only last 5000 IDs to avoid unbounded growth
    items = list(seen)[-5000:]
    STATE_FILE.write_text(json.dumps(items))

def make_id(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]

# ── Sources ───────────────────────────────────────────────────────────────────

def fetch_nvd_cves(hours_back: int = 1) -> list[dict]:
    """NVD API v2 — recent CVEs"""
    vulns = []
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours_back)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        url = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        )
        r = requests.get(url, timeout=20, headers={"User-Agent": "vuln-monitor/1.0"})
        r.raise_for_status()
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "N/A")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d["lang"] == "en"), "No description")
            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            severity = "UNKNOWN"
            # Try CVSSv3.1 first, then v3.0, then v2
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
                    break
            refs = cve.get("references", [])
            ref_url = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            vulns.append({
                "id": cve_id,
                "title": cve_id,
                "description": desc[:300] + ("..." if len(desc) > 300 else ""),
                "severity": severity.upper(),
                "cvss": cvss_score,
                "url": ref_url,
                "source": "NVD/NIST",
                "source_emoji": "🛡️",
            })
        log.info(f"NVD: found {len(vulns)} new CVEs")
    except Exception as e:
        log.error(f"NVD fetch error: {e}")
    return vulns


def fetch_exploitdb() -> list[dict]:
    """Exploit-DB RSS feed"""
    vulns = []
    try:
        feed = feedparser.parse("https://www.exploit-db.com/rss.xml")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if published and published < cutoff:
                continue
            vulns.append({
                "id": make_id(entry.get("link", entry.get("title", ""))),
                "title": entry.get("title", "Unknown exploit"),
                "description": entry.get("summary", "")[:300],
                "severity": "⚠️ 0DAY/EXPLOIT",
                "cvss": "PoC Available",
                "url": entry.get("link", "https://exploit-db.com"),
                "source": "Exploit-DB",
                "source_emoji": "💥",
            })
        log.info(f"Exploit-DB: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"Exploit-DB fetch error: {e}")
    return vulns


def fetch_github_advisories() -> list[dict]:
    """GitHub Security Advisories RSS"""
    vulns = []
    try:
        feed = feedparser.parse("https://github.com/advisories.atom")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if published and published < cutoff:
                continue
            title = entry.get("title", "Unknown Advisory")
            # Extract severity hint from title if present
            severity = "UNKNOWN"
            for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
                if sev in title.upper():
                    severity = sev
                    break
            vulns.append({
                "id": make_id(entry.get("id", title)),
                "title": title,
                "description": entry.get("summary", "")[:300],
                "severity": severity,
                "cvss": "N/A",
                "url": entry.get("link", "https://github.com/advisories"),
                "source": "GitHub Advisories",
                "source_emoji": "🐙",
            })
        log.info(f"GitHub Advisories: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"GitHub Advisories fetch error: {e}")
    return vulns


def fetch_full_disclosure() -> list[dict]:
    """Full Disclosure mailing list via Seclists RSS"""
    vulns = []
    try:
        feed = feedparser.parse("https://seclists.org/rss/fulldisclosure.rss")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            published = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                published = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if published and published < cutoff:
                continue
            vulns.append({
                "id": make_id(entry.get("link", entry.get("title", ""))),
                "title": entry.get("title", "Full Disclosure post"),
                "description": entry.get("summary", "")[:300],
                "severity": "DISCLOSURE",
                "cvss": "N/A",
                "url": entry.get("link", "https://seclists.org/fulldisclosure/"),
                "source": "Full Disclosure",
                "source_emoji": "📢",
            })
        log.info(f"Full Disclosure: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"Full Disclosure fetch error: {e}")
    return vulns


# ── Slack Formatting ──────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL":    "#FF0000",
    "HIGH":        "#FF6600",
    "MEDIUM":      "#FFC000",
    "MODERATE":    "#FFC000",
    "LOW":         "#36A64F",
    "UNKNOWN":     "#888888",
    "DISCLOSURE":  "#4A90D9",
    "⚠️ 0DAY/EXPLOIT": "#FF0000",
}

SEVERITY_BADGE = {
    "CRITICAL":    "🔴 CRITICAL",
    "HIGH":        "🟠 HIGH",
    "MEDIUM":      "🟡 MEDIUM",
    "MODERATE":    "🟡 MODERATE",
    "LOW":         "🟢 LOW",
    "UNKNOWN":     "⚪ UNKNOWN",
    "DISCLOSURE":  "🔵 DISCLOSURE",
    "⚠️ 0DAY/EXPLOIT": "💥 0DAY / EXPLOIT",
}

def build_slack_payload(vuln: dict) -> dict:
    severity = vuln.get("severity", "UNKNOWN").upper()
    color = SEVERITY_COLOR.get(severity, "#888888")
    badge = SEVERITY_BADGE.get(severity, f"⚪ {severity}")
    cvss_text = f"*CVSS:* `{vuln['cvss']}`" if vuln['cvss'] != "N/A" else ""

    return {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{vuln['source_emoji']} *[{vuln['source']}]* {badge}\n"
                                f"*<{vuln['url']}|{vuln['title']}>*"
                            ),
                        },
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": vuln["description"] or "_No description available_",
                        },
                    },
                    *(
                        [{"type": "section", "text": {"type": "mrkdwn", "text": cvss_text}}]
                        if cvss_text else []
                    ),
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": f"🕐 Detected: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                            }
                        ],
                    },
                ],
            }
        ]
    }


def post_to_slack(vuln: dict):
    if not SLACK_WEBHOOK_URL:
        log.warning("SLACK_WEBHOOK_URL not set — skipping Slack post")
        log.info(f"  Would post: [{vuln['source']}] {vuln['title']} ({vuln['severity']})")
        return
    payload = build_slack_payload(vuln)
    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    if r.status_code != 200:
        log.error(f"Slack error {r.status_code}: {r.text}")
    else:
        log.info(f"✅ Posted to Slack: {vuln['title']}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("🔍 Starting vulnerability scan...")
    seen = load_seen()

    all_vulns = []
    all_vulns += fetch_exploitdb()          # fastest 0day source first
    all_vulns += fetch_github_advisories()  # real-time
    all_vulns += fetch_full_disclosure()    # mailing list
    all_vulns += fetch_nvd_cves(hours_back=CHECK_HOURS_BACK)  # authoritative

    new_count = 0
    for vuln in all_vulns:
        uid = vuln["id"]
        if uid in seen:
            continue
        seen.add(uid)
        post_to_slack(vuln)
        new_count += 1

    save_seen(seen)
    log.info(f"✅ Done. {new_count} new vulnerabilities posted out of {len(all_vulns)} fetched.")

if __name__ == "__main__":
    main()
