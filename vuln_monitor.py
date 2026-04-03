#!/usr/bin/env python3
"""
Vulnerability Monitor — Slack Alerting Bot
===========================================
Sources (5 tiers, 35+ feeds):

Tier 1 — Active exploitation:
  CISA KEV, Exploit-DB, Ransomware.live

Tier 2 — Threat intel / dark web alternatives (abuse.ch):
  ThreatFox (IOCs), MalwareBazaar (samples), URLhaus (malware URLs)

Tier 3 — Vendor advisories + fast news (23 feeds, parallel):
  Microsoft MSRC, Cisco, Red Hat, Ubuntu, Debian, Apache, VMware,
  Palo Alto Unit42, Fortinet, SAP, Oracle, F5, Juniper,
  The Hacker News, Bleeping Computer, Packet Storm, Security Week,
  Dark Reading, Krebs, Schneier, Recorded Future, Rapid7, Tenable,
  Securelist (Kaspersky), SANS Internet Storm Center

Tier 4 — Community + research:
  Hacker News, CyberSecurityNews, GitHub Advisories, Full Disclosure

Tier 5 — Authoritative (slow):
  NVD/NIST CVE database
"""

import os
import re
import json
import hashlib
import logging
import requests
import feedparser
from datetime import datetime, timezone, timedelta
from pathlib import Path
from html.parser import HTMLParser

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

def _fmt_dt(dt: datetime | None) -> str:
    """Format a datetime as a clean UTC string, or empty string if None."""
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def fetch_nvd_cves(hours_back: int = 1) -> list[dict]:
    """NVD API v2 — recent CVEs"""
    vulns = []
    try:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours_back)
        fmt   = "%Y-%m-%dT%H:%M:%S.000"
        url   = (
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?pubStartDate={start.strftime(fmt)}&pubEndDate={end.strftime(fmt)}"
        )
        r = requests.get(url, timeout=20, headers={"User-Agent": "vuln-monitor/1.0"})
        r.raise_for_status()
        data = r.json()
        for item in data.get("vulnerabilities", []):
            cve      = item.get("cve", {})
            cve_id   = cve.get("id", "N/A")
            descs    = cve.get("descriptions", [])
            desc     = next((d["value"] for d in descs if d["lang"] == "en"), "No description")
            metrics  = cve.get("metrics", {})
            cvss_score = "N/A"
            severity   = "UNKNOWN"
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    m         = metrics[key][0]
                    cvss_data = m.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity   = cvss_data.get("baseSeverity", m.get("baseSeverity", "UNKNOWN"))
                    break
            refs    = cve.get("references", [])
            ref_url = refs[0]["url"] if refs else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            pub_raw = cve.get("published", "")
            try:
                pub_dt = datetime.fromisoformat(pub_raw.replace("Z", "+00:00")) if pub_raw else None
            except Exception:
                pub_dt = None
            vulns.append({
                "id":           cve_id,
                "title":        cve_id,
                "description":  desc[:300] + ("..." if len(desc) > 300 else ""),
                "severity":     severity.upper(),
                "cvss":         cvss_score,
                "url":          ref_url,
                "source":       "NVD/NIST",
                "source_emoji": "🛡️",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"NVD: found {len(vulns)} new CVEs")
    except Exception as e:
        log.error(f"NVD fetch error: {e}")
    return vulns


def fetch_cisa_kev() -> list[dict]:
    """CISA Known Exploited Vulnerabilities catalogue — JSON feed.
    This is one of the fastest authoritative sources; CloudSEK monitors it closely."""
    vulns = []
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            timeout=20, headers={"User-Agent": "vuln-monitor/1.0"}
        )
        r.raise_for_status()
        data        = r.json()
        cutoff      = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for v in data.get("vulnerabilities", []):
            date_added = v.get("dateAdded", "")
            try:
                pub_dt = datetime.fromisoformat(date_added) if date_added else None
                if pub_dt and pub_dt.tzinfo is None:
                    pub_dt = pub_dt.replace(tzinfo=timezone.utc)
            except Exception:
                pub_dt = None
            # Only alert on entries added within our window
            if pub_dt and pub_dt < cutoff:
                continue
            cve_id  = v.get("cveID", "")
            title   = f"{cve_id} — {v.get('vulnerabilityName', 'Known Exploited Vulnerability')}"
            desc    = (
                f"{v.get('shortDescription', '')} "
                f"| Product: {v.get('product', 'N/A')} ({v.get('vendor', 'N/A')}) "
                f"| Required action: {v.get('requiredAction', 'N/A')}"
            )[:400]
            vulns.append({
                "id":           make_id(cve_id or title),
                "title":        title,
                "description":  desc,
                "severity":     "CRITICAL",   # CISA KEV = always actively exploited
                "cvss":         "N/A",
                "url":          f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "source":       "CISA KEV",
                "source_emoji": "🇺🇸",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"CISA KEV: found {len(vulns)} newly added entries")
    except Exception as e:
        log.error(f"CISA KEV fetch error: {e}")
    return vulns


def fetch_exploitdb() -> list[dict]:
    """Exploit-DB RSS feed"""
    vulns = []
    try:
        feed   = feedparser.parse("https://www.exploit-db.com/rss.xml")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            pub_dt = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if pub_dt and pub_dt < cutoff:
                continue
            vulns.append({
                "id":           make_id(entry.get("link", entry.get("title", ""))),
                "title":        entry.get("title", "Unknown exploit"),
                "description":  entry.get("summary", "")[:300],
                "severity":     "0DAY/EXPLOIT",
                "cvss":         "PoC Available",
                "url":          entry.get("link", "https://exploit-db.com"),
                "source":       "Exploit-DB",
                "source_emoji": "💥",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"Exploit-DB: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"Exploit-DB fetch error: {e}")
    return vulns


def fetch_github_advisories() -> list[dict]:
    """GitHub Security Advisories RSS"""
    vulns = []
    try:
        feed   = feedparser.parse("https://github.com/advisories.atom")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            pub_dt = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if pub_dt and pub_dt < cutoff:
                continue
            title    = entry.get("title", "Unknown Advisory")
            severity = "UNKNOWN"
            for sev in ["CRITICAL", "HIGH", "MODERATE", "LOW"]:
                if sev in title.upper():
                    severity = sev
                    break
            vulns.append({
                "id":           make_id(entry.get("id", title)),
                "title":        title,
                "description":  entry.get("summary", "")[:300],
                "severity":     severity,
                "cvss":         "N/A",
                "url":          entry.get("link", "https://github.com/advisories"),
                "source":       "GitHub Advisories",
                "source_emoji": "🐙",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"GitHub Advisories: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"GitHub Advisories fetch error: {e}")
    return vulns


def fetch_full_disclosure() -> list[dict]:
    """Full Disclosure mailing list via Seclists RSS"""
    vulns = []
    try:
        feed   = feedparser.parse("https://seclists.org/rss/fulldisclosure.rss")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            pub_dt = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if pub_dt and pub_dt < cutoff:
                continue
            vulns.append({
                "id":           make_id(entry.get("link", entry.get("title", ""))),
                "title":        entry.get("title", "Full Disclosure post"),
                "description":  entry.get("summary", "")[:300],
                "severity":     "DISCLOSURE",
                "cvss":         "N/A",
                "url":          entry.get("link", "https://seclists.org/fulldisclosure/"),
                "source":       "Full Disclosure",
                "source_emoji": "📢",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"Full Disclosure: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"Full Disclosure fetch error: {e}")
    return vulns


# Security-related keywords to filter HN posts
HN_SECURITY_KEYWORDS = [
    "cve", "vulnerability", "vuln", "exploit", "rce", "zero-day", "0day",
    "remote code", "sql injection", "xss", "buffer overflow", "privilege escalation",
    "ransomware", "malware", "backdoor", "breach", "hack", "patch", "advisory",
    "security flaw", "attack", "critical bug", "auth bypass", "injection",
    "data leak", "exposure", "disclosure",
]

def fetch_hackernews() -> list[dict]:
    """Hacker News Algolia API — security-related stories from the last hour"""
    vulns = []
    try:
        cutoff_ts = int((datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)).timestamp())
        url = (
            "https://hn.algolia.com/api/v1/search_by_date"
            f"?tags=story&numericFilters=created_at_i>{cutoff_ts}&hitsPerPage=50"
            "&query=vulnerability+OR+exploit+OR+CVE+OR+zero-day+OR+security+breach"
        )
        r = requests.get(url, timeout=15, headers={"User-Agent": "vuln-monitor/1.0"})
        r.raise_for_status()
        data = r.json()
        for hit in data.get("hits", []):
            title = hit.get("title", "")
            if not any(kw in title.lower() for kw in HN_SECURITY_KEYWORDS):
                continue
            story_url  = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID','')}"
            hn_url     = f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}"
            points     = hit.get("points", 0) or 0
            comments   = hit.get("num_comments", 0) or 0
            created_ts = hit.get("created_at_i")
            pub_dt     = datetime.fromtimestamp(created_ts, tz=timezone.utc) if created_ts else None
            desc       = f"Points: {points} | Comments: {comments} | Discussion: {hn_url}"
            vulns.append({
                "id":           make_id(hit.get("objectID", title)),
                "title":        title,
                "description":  desc,
                "severity":     "NEWS",
                "cvss":         "N/A",
                "url":          story_url,
                "source":       "Hacker News",
                "source_emoji": "🟠",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"Hacker News: found {len(vulns)} security stories")
    except Exception as e:
        log.error(f"Hacker News fetch error: {e}")
    return vulns


class _TextExtractor(HTMLParser):
    """Strips HTML tags from a string."""
    def __init__(self):
        super().__init__()
        self._parts = []
    def handle_data(self, data):
        self._parts.append(data)
    def get_text(self):
        return " ".join(self._parts).strip()

def _strip_html(html: str) -> str:
    p = _TextExtractor()
    p.feed(html)
    return p.get_text()


def fetch_cybersecuritynews() -> list[dict]:
    """CyberSecurityNews.com RSS feed"""
    vulns = []
    try:
        feed   = feedparser.parse("https://cybersecuritynews.com/feed/")
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
        for entry in feed.entries:
            pub_dt = None
            if hasattr(entry, "published_parsed") and entry.published_parsed:
                pub_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
            if pub_dt and pub_dt < cutoff:
                continue
            title       = entry.get("title", "CyberSecurityNews article")
            raw_summary = entry.get("summary", "") or ""
            summary     = _strip_html(raw_summary)[:300]
            if not summary:
                content = entry.get("content", [{}])[0].get("value", "")
                summary = _strip_html(content)[:300]
            severity  = "NEWS"
            title_up  = title.upper()
            if any(w in title_up for w in ["CRITICAL", "0-DAY", "ZERO-DAY", "RCE", "REMOTE CODE"]):
                severity = "CRITICAL"
            elif any(w in title_up for w in ["HIGH", "EXPLOIT", "RANSOMWARE", "BREACH"]):
                severity = "HIGH"
            vulns.append({
                "id":           make_id(entry.get("link", title)),
                "title":        title,
                "description":  summary or "_No description available_",
                "severity":     severity,
                "cvss":         "N/A",
                "url":          entry.get("link", "https://cybersecuritynews.com"),
                "source":       "CyberSecurityNews",
                "source_emoji": "📰",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"CyberSecurityNews: found {len(vulns)} entries")
    except Exception as e:
        log.error(f"CyberSecurityNews fetch error: {e}")
    return vulns


# ── Vuln Category Classifier ──────────────────────────────────────────────────
# Maps category name → (emoji, keywords to match in title+description)

CATEGORY_RULES = [
    ("💀 Zero-Day / 0day",   ["0day", "zero-day", "zero day", "0-day", "in the wild", "actively exploited", "poc", "proof of concept"]),
    ("🌐 Web / AppSec",      ["xss", "cross-site", "csrf", "sql injection", "sqli", "ssrf", "ssti", "rce", "remote code execution",
                               "deserialization", "xxe", "path traversal", "directory traversal", "open redirect",
                               "injection", "web application", "api vulnerability", "oauth", "jwt", "authentication bypass",
                               "broken access", "idor", "cors", "click hijack"]),
    ("🏗️ Infrastructure",    ["linux", "windows server", "active directory", "ldap", "kerberos", "smb", "rdp", "ssh",
                               "network device", "router", "firewall", "vpn", "dns", "dhcp", "nfs", "samba",
                               "privilege escalation", "local privilege", "kernel", "driver", "firmware",
                               "container escape", "docker", "kubernetes", "k8s", "hypervisor", "vmware", "esxi"]),
    ("☁️ Cloud",             ["aws", "azure", "gcp", "google cloud", "s3 bucket", "iam", "cloud storage",
                               "lambda", "cloud function", "serverless", "cloud misconfiguration", "ecr",
                               "eks", "aks", "gke", "cloudtrail", "azure ad", "entra", "okta", "iam role"]),
    ("🔓 Data Breach",       ["data breach", "data leak", "data exposure", "leaked", "exposed database",
                               "credentials leaked", "pii exposed", "personal data", "sensitive data",
                               "database dump", "records exposed", "exfiltration", "data theft", "stolen data"]),
    ("🦠 Malware / Ransomware", ["ransomware", "malware", "trojan", "backdoor", "rootkit", "spyware",
                                  "worm", "botnet", "rat ", "remote access trojan", "infostealer",
                                  "keylogger", "cryptominer", "dropper", "c2", "command and control",
                                  "lockbit", "alphv", "blackcat", "cl0p", "blackbasta", "akira",
                                  "play ransomware", "rhysida", "hunters"]),
    ("🦊 Threat Intel / IOC",   ["ioc", "indicator of compromise", "c2 server", "malware url",
                                  "phishing domain", "threat actor", "apt", "campaign", "ttps",
                                  "malware bazaar", "threatfox", "urlhaus", "hash", "sha256"]),
    ("📦 Supply Chain",      ["supply chain", "dependency", "npm package", "pypi", "rubygems", "maven",
                               "open source", "third-party", "software bill", "sbom", "package hijack",
                               "typosquat", "dependency confusion", "malicious package"]),
    ("🔐 Crypto / Auth",     ["cryptographic", "tls", "ssl", "certificate", "openssl", "encryption",
                               "weak cipher", "hash collision", "key exposure", "auth bypass",
                               "password", "credential", "multi-factor", "mfa bypass", "saml"]),
    ("📱 Mobile",            ["android", "ios", "iphone", "mobile app", "apk", "swift", "webkit",
                               "mobile browser", "play store", "app store"]),
    ("🏭 ICS / OT / SCADA",  ["scada", "ics", "ot security", "industrial control", "plc", "hmi",
                               "modbus", "dnp3", "operational technology", "critical infrastructure"]),
    ("🔔 Security News",     ["patch tuesday", "security advisory", "cve assigned", "vulnerability disclosed",
                               "security update", "security bulletin"]),
]

def classify_category(title: str, description: str) -> tuple[str, str]:
    """Returns (category_label, category_emoji) based on keyword matching."""
    text = (title + " " + description).lower()
    for label, keywords in CATEGORY_RULES:
        if any(kw in text for kw in keywords):
            emoji, name = label.split(" ", 1)
            return name.strip(), emoji.strip()
    return "General / Other", "🔎"


# ── Severity Config ───────────────────────────────────────────────────────────

SEVERITY_COLOR = {
    "CRITICAL":         "#CC0000",
    "HIGH":             "#E05C00",
    "MEDIUM":           "#D4A000",
    "MODERATE":         "#D4A000",
    "LOW":              "#2E7D32",
    "UNKNOWN":          "#666666",
    "DISCLOSURE":       "#1565C0",
    "NEWS":             "#4527A0",
    "0DAY/EXPLOIT":     "#CC0000",
}

SEVERITY_EMOJI = {
    "CRITICAL":         "🔴",
    "HIGH":             "🟠",
    "MEDIUM":           "🟡",
    "MODERATE":         "🟡",
    "LOW":              "🟢",
    "UNKNOWN":          "⚪",
    "DISCLOSURE":       "🔵",
    "NEWS":             "📰",
    "0DAY/EXPLOIT":     "💥",
}

def _normalise_severity(raw: str) -> str:
    s = raw.upper().replace("⚠️ ", "").replace("/", "").strip()
    if "0DAY" in s or "EXPLOIT" in s:
        return "0DAY/EXPLOIT"
    return s


# ── Rich Slack Payload Builder ────────────────────────────────────────────────

def build_slack_payload(vuln: dict) -> dict:
    sev_raw       = vuln.get("severity", "UNKNOWN")
    sev           = _normalise_severity(sev_raw)
    color         = SEVERITY_COLOR.get(sev, "#666666")
    sev_emoji     = SEVERITY_EMOJI.get(sev, "⚪")
    cvss          = vuln.get("cvss", "N/A")
    source        = vuln.get("source", "Unknown")
    source_emoji  = vuln.get("source_emoji", "🔎")
    title         = vuln.get("title", "Unknown Vulnerability")
    url           = vuln.get("url", "")
    description   = vuln.get("description") or "_No description available._"
    published     = vuln.get("published", "")   # original source timestamp
    detected      = vuln.get("detected", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    # Category classification
    cat_name, cat_emoji = classify_category(title, description)

    # CVE ID extraction (if present anywhere in title/desc)
    cve_match = re.search(r"CVE-\d{4}-\d+", title + " " + description, re.IGNORECASE)
    cve_id    = cve_match.group(0).upper() if cve_match else None

    # ── Header line ──
    header_parts = [f"{source_emoji} *[{source}]*", f"{sev_emoji} *{sev}*"]
    if cve_id:
        header_parts.append(f"`{cve_id}`")
    header = "  |  ".join(header_parts)

    # ── Fields row (2-column layout) ──
    fields = [
        {"type": "mrkdwn", "text": f"*Category*\n{cat_emoji} {cat_name}"},
        {"type": "mrkdwn", "text": f"*Severity*\n{sev_emoji} {sev}"},
    ]
    if cvss != "N/A":
        fields.append({"type": "mrkdwn", "text": f"*CVSS Score*\n`{cvss}`"})
    if cve_id:
        fields.append({"type": "mrkdwn", "text": f"*CVE ID*\n<https://nvd.nist.gov/vuln/detail/{cve_id}|{cve_id}>"})

    # ── Timestamps ──
    ts_parts = [f"⏱ *Detected:* {detected}"]
    if published:
        ts_parts.append(f"📅 *Published:* {published}")
    if published and published != detected:
        ts_parts.append("_(source timestamp — matches original disclosure)_")

    blocks = [
        # Header with source + severity + CVE
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{header}\n*<{url}|{title}>*"}},
        {"type": "divider"},
        # Description
        {"type": "section", "text": {"type": "mrkdwn", "text": description[:400]}},
        # Fields grid
        {"type": "section", "fields": fields},
        {"type": "divider"},
        # Timestamps footer
        {"type": "context", "elements": [{"type": "mrkdwn", "text": "   ".join(ts_parts)}]},
    ]

    return {"attachments": [{"color": color, "blocks": blocks}]}


def post_to_slack(vuln: dict):
    if not SLACK_WEBHOOK_URL:
        log.warning("SLACK_WEBHOOK_URL not set — skipping Slack post")
        log.info(f"  Would post: [{vuln['source']}] {vuln['title']} ({vuln.get('severity')})")
        return
    payload = build_slack_payload(vuln)
    r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
    if r.status_code != 200:
        log.error(f"Slack error {r.status_code}: {r.text}")
    else:
        log.info(f"✅ Posted to Slack: {vuln['title']}")


# ── Vendor Advisories + Fast News RSS Feeds ───────────────────────────────────
# These post vulns BEFORE NVD processes them — closing the CloudSEK speed gap.
# Each entry: (source_name, source_emoji, feed_url, default_severity)

VENDOR_FEEDS = [
    # ── Tier 1: Vendor advisories (post before NVD, often hours/days earlier) ──
    ("Microsoft MSRC",       "🪟", "https://api.msrc.microsoft.com/update-guide/rss",                          "HIGH"),
    ("Cisco Advisories",     "🔵", "https://tools.cisco.com/security/center/psirtrss20.xml",                   "HIGH"),
    ("Red Hat Security",     "🎩", "https://access.redhat.com/security/vulnerabilities/rss",                   "HIGH"),
    ("Ubuntu Security",      "🟠", "https://ubuntu.com/security/notices/rss.xml",                              "MEDIUM"),
    ("Debian Security",      "🌀", "https://www.debian.org/security/dsa-long",                                 "MEDIUM"),
    ("Apache Security",      "🪶", "https://httpd.apache.org/security/vulnerabilities-httpd.xml",              "HIGH"),
    ("VMware Security",      "💠", "https://www.vmware.com/security/advisories/rss-feed.xml",                  "HIGH"),
    ("Palo Alto Unit42",     "🔥", "https://unit42.paloaltonetworks.com/feed/",                                "HIGH"),
    ("Fortinet PSIRT",       "🛡", "https://www.fortiguard.com/rss/ir.xml",                                    "HIGH"),
    ("SAP Security",         "🔷", "https://www.sap.com/cgi-bin/sap/rss/securitynotes.rss",                   "HIGH"),
    ("Oracle Security",      "🔴", "https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-security-alerts.xml", "HIGH"),
    ("F5 Security",          "⚙️", "https://support.f5.com/csp/api/v1/feeds/rss/public_advisories",           "HIGH"),
    ("Juniper Security",     "🌿", "https://kb.juniper.net/InfoCenter/index?page=content&channel=SECURITY_ADVISORIES&rss", "HIGH"),

    # ── Tier 2: Fast security news (breaks stories before NVD) ──────────────────
    ("The Hacker News",      "📡", "https://feeds.feedburner.com/TheHackersNews",                              "NEWS"),
    ("Bleeping Computer",    "💻", "https://www.bleepingcomputer.com/feed/",                                   "NEWS"),
    ("Packet Storm",         "⚡", "https://rss.packetstormsecurity.com/files/",                               "NEWS"),
    ("Security Week",        "📊", "https://feeds.feedburner.com/securityweek",                                "NEWS"),
    ("Dark Reading",         "🌑", "https://www.darkreading.com/rss.xml",                                      "NEWS"),
    ("Krebs on Security",    "🕵️", "https://krebsonsecurity.com/feed/",                                       "NEWS"),
    ("Schneier on Security", "🔒", "https://www.schneier.com/feed/atom/",                                      "NEWS"),
    ("Recorded Future",      "📈", "https://www.recordedfuture.com/feed",                                      "NEWS"),
    ("Rapid7 Blog",          "🚀", "https://blog.rapid7.com/rss/",                                             "NEWS"),
    ("Tenable Blog",         "🔭", "https://www.tenable.com/blog/feed",                                        "NEWS"),
    ("Securelist (Kaspersky)","🧅", "https://securelist.com/feed/",                                            "NEWS"),
    ("SANS Internet Storm",  "🌩️", "https://isc.sans.edu/rssfeed_full.xml",                                   "HIGH"),
]

# Keywords to filter news feeds — skip unrelated articles
NEWS_SECURITY_KEYWORDS = [
    "cve", "vulnerabilit", "exploit", "zero-day", "0day", "rce", "patch",
    "advisory", "breach", "malware", "ransomware", "backdoor", "attack",
    "injection", "overflow", "escalation", "bypass", "disclosure", "poc",
    "critical", "actively exploited", "remote code", "data leak", "exposed",
]

def _is_security_relevant(title: str, summary: str) -> bool:
    text = (title + " " + summary).lower()
    return any(kw in text for kw in NEWS_SECURITY_KEYWORDS)

def fetch_vendor_and_news_feeds() -> list[dict]:
    """Bulk fetch all vendor advisory + fast news RSS feeds in parallel."""
    import concurrent.futures
    results = []

    def _fetch_one(feed_tuple):
        source, emoji, url, default_sev = feed_tuple
        items = []
        try:
            feed   = feedparser.parse(url)
            cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)
            for entry in feed.entries:
                pub_dt = None
                if hasattr(entry, "published_parsed") and entry.published_parsed:
                    try:
                        pub_dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
                    except Exception:
                        pass
                if pub_dt and pub_dt < cutoff:
                    continue

                title   = entry.get("title", "").strip()
                summary = _strip_html(entry.get("summary", "") or "")[:300]

                if not title:
                    continue

                # For news feeds (not vendor advisories), filter by keywords
                if default_sev == "NEWS" and not _is_security_relevant(title, summary):
                    continue

                # Infer severity from title for news feeds
                sev = default_sev
                if default_sev == "NEWS":
                    t = title.upper()
                    if any(w in t for w in ["CRITICAL", "ZERO-DAY", "0-DAY", "RCE", "ACTIVELY EXPLOITED"]):
                        sev = "CRITICAL"
                    elif any(w in t for w in ["HIGH", "EXPLOIT", "RANSOMWARE", "BREACH", "BACKDOOR"]):
                        sev = "HIGH"

                items.append({
                    "id":           make_id(entry.get("link", title) + source),
                    "title":        title,
                    "description":  summary or "_No description available._",
                    "severity":     sev,
                    "cvss":         "N/A",
                    "url":          entry.get("link", url),
                    "source":       source,
                    "source_emoji": emoji,
                    "published":    _fmt_dt(pub_dt),
                    "detected":     _fmt_dt(datetime.now(timezone.utc)),
                })
            if items:
                log.info(f"{source}: {len(items)} new items")
        except Exception as e:
            log.warning(f"{source} feed error: {e}")
        return items

    # Fetch all feeds concurrently — much faster than sequential
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(_fetch_one, f): f for f in VENDOR_FEEDS}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.extend(future.result())
            except Exception as e:
                log.warning(f"Feed thread error: {e}")

    log.info(f"Vendor+News feeds total: {len(results)} items")
    return results


# ── Dark Web Intelligence (Free Legal Sources) ────────────────────────────────

def fetch_ransomware_live() -> list[dict]:
    """Ransomware.live — aggregates ALL active ransomware gang leak sites.
    Catches victim announcements from LockBit, ALPHV, Cl0p, BlackBasta etc.
    This is the closest free alternative to paid dark web monitoring."""
    vulns = []
    try:
        # Recent victims endpoint — posted by ransomware gangs on their leak sites
        r = requests.get(
            "https://api.ransomware.live/recentvictims",
            timeout=15,
            headers={"User-Agent": "vuln-monitor/1.0", "Accept": "application/json"}
        )
        r.raise_for_status()
        victims  = r.json()
        cutoff   = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)

        for v in victims if isinstance(victims, list) else []:
            # Parse the discovered timestamp
            pub_dt = None
            for ts_field in ["discovered", "published", "date"]:
                raw = v.get(ts_field, "")
                if raw:
                    try:
                        pub_dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                        if pub_dt.tzinfo is None:
                            pub_dt = pub_dt.replace(tzinfo=timezone.utc)
                        break
                    except Exception:
                        pass
            if pub_dt and pub_dt < cutoff:
                continue

            group    = v.get("group_name", v.get("group", "Unknown Group")).upper()
            victim   = v.get("victim", v.get("company", "Unknown Victim"))
            country  = v.get("country", "")
            sector   = v.get("activity", v.get("sector", ""))
            website  = v.get("website", "")
            desc_parts = [f"Ransomware group *{group}* claimed attack on *{victim}*."]
            if sector:
                desc_parts.append(f"Sector: {sector}.")
            if country:
                desc_parts.append(f"Country: {country}.")
            if website:
                desc_parts.append(f"Target site: {website}")

            vulns.append({
                "id":           make_id(f"{group}-{victim}-{v.get('discovered','')}"),
                "title":        f"[Ransomware] {group} → {victim}",
                "description":  " ".join(desc_parts),
                "severity":     "CRITICAL",
                "cvss":         "N/A",
                "url":          f"https://www.ransomware.live/group/{group.lower().replace(' ','-')}",
                "source":       "Ransomware.live",
                "source_emoji": "🦠",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"Ransomware.live: {len(vulns)} new victims")
    except Exception as e:
        log.error(f"Ransomware.live fetch error: {e}")
    return vulns


def fetch_malware_bazaar() -> list[dict]:
    """MalwareBazaar (abuse.ch) — fresh malware samples uploaded in the last hour.
    Catches new malware families before AV vendors even have signatures."""
    vulns = []
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_recent", "selector": "time"},
            timeout=15,
            headers={"User-Agent": "vuln-monitor/1.0"}
        )
        r.raise_for_status()
        data   = r.json()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)

        for sample in data.get("data", []):
            raw = sample.get("first_seen", "")
            try:
                pub_dt = datetime.fromisoformat(raw.replace(" ", "T") + "+00:00") if raw else None
            except Exception:
                pub_dt = None
            if pub_dt and pub_dt < cutoff:
                continue

            tags      = ", ".join(sample.get("tags") or []) or "N/A"
            family    = sample.get("signature") or "Unknown"
            file_type = sample.get("file_type", "N/A")
            sha256    = sample.get("sha256_hash", "")
            reporter  = sample.get("reporter", "anonymous")
            desc      = (
                f"New *{family}* sample ({file_type}). "
                f"Tags: {tags}. "
                f"Reported by: {reporter}. "
                f"SHA256: `{sha256[:20]}...`"
            )
            vulns.append({
                "id":           make_id(sha256 or desc),
                "title":        f"[Malware] New {family} sample — {file_type}",
                "description":  desc,
                "severity":     "HIGH",
                "cvss":         "N/A",
                "url":          f"https://bazaar.abuse.ch/sample/{sha256}/" if sha256 else "https://bazaar.abuse.ch/",
                "source":       "MalwareBazaar",
                "source_emoji": "🧫",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"MalwareBazaar: {len(vulns)} new samples")
    except Exception as e:
        log.error(f"MalwareBazaar fetch error: {e}")
    return vulns


def fetch_threatfox() -> list[dict]:
    """ThreatFox (abuse.ch) — fresh IOCs (IPs, domains, URLs, hashes) from threat actors.
    Catches C2 infrastructure, phishing domains, and malware distribution URLs."""
    vulns = []
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
            timeout=15,
            headers={"User-Agent": "vuln-monitor/1.0"}
        )
        r.raise_for_status()
        data   = r.json()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)

        seen_malware = set()  # deduplicate by malware family per run
        for ioc in data.get("data", []):
            raw = ioc.get("first_seen", "")
            try:
                pub_dt = datetime.fromisoformat(raw.replace(" ", "T") + "+00:00") if raw else None
            except Exception:
                pub_dt = None
            if pub_dt and pub_dt < cutoff:
                continue

            malware   = ioc.get("malware", "Unknown")
            ioc_type  = ioc.get("ioc_type", "N/A")
            ioc_val   = ioc.get("ioc", "N/A")
            tags      = ", ".join(ioc.get("tags") or []) or "N/A"
            confidence= ioc.get("confidence_level", "N/A")
            threat    = ioc.get("threat_type", "N/A")

            # Group by malware family to avoid 100 alerts for one campaign
            dedup_key = make_id(malware + str(pub_dt.date() if pub_dt else ""))
            if dedup_key in seen_malware:
                continue
            seen_malware.add(dedup_key)

            desc = (
                f"*{malware}* IOC detected. "
                f"Type: {ioc_type} | Threat: {threat} | "
                f"Confidence: {confidence}% | Tags: {tags}. "
                f"Sample IOC: `{ioc_val[:60]}`"
            )
            vulns.append({
                "id":           dedup_key,
                "title":        f"[Threat Intel] {malware} — {ioc_type} IOC",
                "description":  desc,
                "severity":     "HIGH" if int(confidence or 0) >= 75 else "MEDIUM",
                "cvss":         "N/A",
                "url":          f"https://threatfox.abuse.ch/browse.php?search=malware%3A{malware}",
                "source":       "ThreatFox",
                "source_emoji": "🦊",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"ThreatFox: {len(vulns)} new malware families with IOCs")
    except Exception as e:
        log.error(f"ThreatFox fetch error: {e}")
    return vulns


def fetch_urlhaus() -> list[dict]:
    """URLhaus (abuse.ch) — active malware distribution URLs.
    Catches phishing and malware delivery infrastructure in real-time."""
    vulns = []
    try:
        r = requests.get(
            "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/",
            timeout=15,
            headers={"User-Agent": "vuln-monitor/1.0"}
        )
        r.raise_for_status()
        data   = r.json()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=CHECK_HOURS_BACK)

        seen_tags = set()  # group by malware tag
        for entry in data.get("urls", []):
            raw = entry.get("date_added", "")
            try:
                pub_dt = datetime.fromisoformat(raw.replace(" ", "T") + "+00:00") if raw else None
            except Exception:
                pub_dt = None
            if pub_dt and pub_dt < cutoff:
                continue

            tags     = [t.get("tag", "") for t in (entry.get("tags") or [])]
            tag_str  = ", ".join(tags) or "untagged"
            url_val  = entry.get("url", "N/A")
            status   = entry.get("url_status", "unknown")
            host     = entry.get("host", "N/A")

            # Deduplicate by tag group
            dedup_key = make_id(tag_str + str(pub_dt.date() if pub_dt else ""))
            if dedup_key in seen_tags:
                continue
            seen_tags.add(dedup_key)

            desc = (
                f"Active malware URL detected. "
                f"Tags: *{tag_str}* | Host: `{host}` | Status: {status}. "
                f"URL: `{url_val[:80]}`"
            )
            vulns.append({
                "id":           dedup_key,
                "title":        f"[URLhaus] Active malware URL — {tag_str}",
                "description":  desc,
                "severity":     "HIGH",
                "cvss":         "N/A",
                "url":          f"https://urlhaus.abuse.ch/host/{host}/",
                "source":       "URLhaus",
                "source_emoji": "🔗",
                "published":    _fmt_dt(pub_dt),
                "detected":     _fmt_dt(datetime.now(timezone.utc)),
            })
        log.info(f"URLhaus: {len(vulns)} new malware URL groups")
    except Exception as e:
        log.error(f"URLhaus fetch error: {e}")
    return vulns


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("🔍 Starting vulnerability scan...")
    seen = load_seen()

    all_vulns = []

    # ── Tier 1: Active exploitation + 0days (fastest, highest severity) ──
    all_vulns += fetch_cisa_kev()              # 🇺🇸 CISA known exploited vulns
    all_vulns += fetch_exploitdb()             # 💥 0days & public PoCs
    all_vulns += fetch_ransomware_live()       # 🦠 ransomware gang victim announcements

    # ── Tier 2: Threat intel / dark web alternatives (abuse.ch trio) ──
    all_vulns += fetch_threatfox()             # 🦊 IOCs from active threat actors
    all_vulns += fetch_malware_bazaar()        # 🧫 fresh malware samples
    all_vulns += fetch_urlhaus()               # 🔗 active malware distribution URLs

    # ── Tier 3: Vendor advisories + fast news (parallel, 23 feeds) ──
    all_vulns += fetch_vendor_and_news_feeds() # 🏭 Microsoft, Cisco, RedHat, BleepingComputer...

    # ── Tier 4: Community + research sources ──
    all_vulns += fetch_hackernews()            # 🟠 community breaks news early
    all_vulns += fetch_cybersecuritynews()     # 📰 dedicated security journalism
    all_vulns += fetch_github_advisories()     # 🐙 package advisories
    all_vulns += fetch_full_disclosure()       # 📢 researcher mailing list

    # ── Tier 5: Authoritative but slow ──
    all_vulns += fetch_nvd_cves(hours_back=CHECK_HOURS_BACK)  # 🛡️ NVD — lags 24-48hr

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
