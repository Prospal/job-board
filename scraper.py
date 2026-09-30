#!/usr/bin/env python3
"""
Cyber security job scraper -> jobs.csv

Sources:
  * Company career APIs (Greenhouse / Lever / Ashby) -> DIRECT apply links
  * Remote job boards (Remotive / RemoteOK / Jobicy)  -> listing page (apply button is there)

Standard library only. Run:  python3 scraper.py
"""

import csv
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date

# ─────────────────────────── CONFIG ───────────────────────────

# Plain results stay local (git-ignored). The GitHub workflow encrypts them into docs/*.enc
# so the public repo / Pages site only ever holds password-protected data.
OUTPUT_CSV = "data/jobs.csv"
OUTPUT_JSON = "data/jobs.json"

# Companies to pull straight from their applicant-tracking system.
# Add more: find the slug in their careers URL, e.g.
#   boards.greenhouse.io/<slug>, jobs.lever.co/<slug>, jobs.ashbyhq.com/<slug>
GREENHOUSE = [
    "cloudflare", "datadog", "okta", "gitlab", "stripe", "coinbase", "mongodb",
    "elastic", "zscaler", "bybit", "gemini", "mercari", "paypay", "agoda", "careem",
]
LEVER = ["binance", "kraken"]
ASHBY = ["coinbase", "airwallex", "wiz", "1password", "binance"]
# Workday: (tenant, wd-server, site) from <tenant>.<wd>.myworkdayjobs.com/<site>
WORKDAY = [
    ("crowdstrike", "wd5", "crowdstrikecareers"),
    ("cisco", "wd5", "Cisco_Careers"),
    ("mastercard", "wd1", "CorporateCareers"),
    ("visa", "wd5", "Visa"),
    ("salesforce", "wd12", "External_Career_Site"),
    ("nvidia", "wd5", "NVIDIAExternalCareerSite"),
    ("intel", "wd1", "External"),
]
WORKDAY_SEARCH = ["security", "cyber"]

# Gulf / Asia job boards.
BAYT_COUNTRIES = ["qatar", "uae", "saudi-arabia", "bahrain", "kuwait", "oman"]
BAYT_QUERIES = ["cyber-security", "information-security", "soc-analyst", "penetration-tester"]
GULFTALENT_QUERIES = ["cyber security", "information security", "soc analyst", "penetration tester"]

# LinkedIn public (logged-out) search. Low volume + slow on purpose; set to [] to disable.
LINKEDIN_LOCATIONS = ["Singapore", "Japan", "Qatar", "United Arab Emirates", "Saudi Arabia",
                      "Hong Kong", "Malaysia", "Netherlands", "Ireland"]
LINKEDIN_QUERIES = ["cyber security", "SOC analyst", "penetration tester", "security engineer"]
LINKEDIN_PAGES = 2       # 10 jobs per page
LINKEDIN_DELAY = 2.0     # seconds between LinkedIn requests

# A job title must match one of these to be kept.
TITLE_KEYWORDS = [
    "security", "secops", "soc ", "soc analyst", "cyber", "pentest", "penetration",
    "red team", "blue team", "threat", "incident response", "dfir", "forensic",
    "vulnerability", "appsec", "application security", "cloud security", "grc",
    "iam", "identity", "detection", "malware", "offensive", "infosec", "ciso",
]
# Titles containing these are dropped (physical security, sales, etc.).
TITLE_EXCLUDE = ["security guard", "security officer", "sales", "account executive",
                 "marketing", "recruiter", "securities"]

# Onsite jobs are kept only in these countries (English-friendly, relocation common).
# Country -> words that identify it in a job's location text (matched as whole words).
TARGET_COUNTRIES = {
    "Singapore": ["singapore"],
    "Japan": ["japan", "tokyo", "osaka"],
    "Qatar": ["qatar", "doha"],
    "UAE": ["united arab emirates", "uae", "dubai", "abu dhabi"],
    "Saudi Arabia": ["saudi", "riyadh", "jeddah", "ksa"],
    "Bahrain": ["bahrain", "manama"],
    "Kuwait": ["kuwait"],
    "Oman": ["oman", "muscat"],
    "Hong Kong": ["hong kong"],
    "Malaysia": ["malaysia", "kuala lumpur"],
    "Netherlands": ["netherlands", "amsterdam"],
    "Ireland": ["ireland", "dublin"],
    "Luxembourg": ["luxembourg"],
    "Germany": ["germany", "berlin"],
    "United Kingdom": ["united kingdom", "london"],
    "Estonia": ["estonia", "tallinn"],
    "Australia": ["australia", "sydney", "melbourne"],
}
_COUNTRY_RE = [(name, re.compile(r"\b(" + "|".join(map(re.escape, words)) + r")\b"))
               for name, words in TARGET_COUNTRIES.items()]
REMOTE_WORDS = ["remote", "anywhere", "worldwide", "global", "distributed"]

# Remote jobs locked to these regions are flagged (you probably can't take them).
REMOTE_RESTRICTED = ["us only", "usa only", "united states only", "must be based in the us",
                     "us-based", "canada only", "uk only", "eu only"]

RELOCATION_PATTERNS = [r"relocation", r"relocate", r"visa sponsor", r"sponsor(ship)? (a |your )?visa",
                       r"work permit", r"visa support", r"moving allowance"]
NO_SPONSOR_PATTERNS = [r"(not|unable to|cannot|can't|won't) (provide |offer )?(visa )?sponsor",
                       r"no (visa )?sponsorship", r"must (already )?(have|hold) (the )?(right|authori[sz]ation) to work"]
# Jobs only for citizens or security-cleared people -> flagged.
RESTRICTED_PATTERNS = [r"(uae|qatari|saudi|omani|kuwaiti|bahraini|emirati) nationals?",
                       r"nationals? only", r"omani only", r"emirati\b",
                       r"clearance", r"ts/sci", r"top secret", r"citizens? only"]
# Non-English language requirements -> flagged.
LANGUAGE_PATTERNS = [r"japanese", r"\bjlpt\b", r"\bn[12]\b", r"arabic", r"mandarin", r"cantonese",
                     r"german \(?(c1|b2|fluent)", r"fluent (in )?german", r"dutch", r"bahasa", r"korean"]

# Skills detected in job descriptions: category -> {skill name: regex on lowercase text}.
# Powers the dashboard's Skills tab and skill filter.
SKILLS = {
    "SIEM & monitoring": {
        "SIEM": r"\bsiem\b", "Splunk": r"splunk", "Microsoft Sentinel": r"\bsentinel\b(?!one)",
        "QRadar": r"qradar", "Elastic / ELK": r"\belastic(search)?\b|\belk\b", "SOAR": r"\bsoar\b",
    },
    "Endpoint (EDR/XDR)": {
        "EDR / XDR": r"\b[ex]dr\b", "CrowdStrike": r"crowdstrike|falcon", "Microsoft Defender": r"defender",
        "SentinelOne": r"sentinel ?one", "Carbon Black": r"carbon black",
    },
    "Security operations": {
        "Incident response": r"incident (response|handling)|\bdfir\b", "Threat hunting": r"threat hunt",
        "Threat intelligence": r"threat intel|\bcti\b", "Digital forensics": r"forensic",
        "Malware analysis": r"malware analy|reverse engineer", "Detection engineering": r"detection (engineering|rules?|content)|sigma rules?|\byara\b",
        "Vulnerability management": r"vulnerability (management|assessment|scann)", "SOC": r"\bsoc\b(?! ?2)",
    },
    "Offensive security": {
        "Penetration testing": r"penetration test|\bpen ?test", "Red teaming": r"red team",
        "Burp Suite": r"burp", "Metasploit": r"metasploit", "OWASP": r"owasp", "Bug bounty": r"bug bounty",
    },
    "Cloud & platform": {
        "AWS": r"\baws\b|amazon web services", "Azure": r"\bazure\b", "GCP": r"\bgcp\b|google cloud",
        "Kubernetes": r"kubernetes|\bk8s\b", "Docker / containers": r"docker|container", "Terraform / IaC": r"terraform|infrastructure as code|\biac\b",
        "Cloud security (CSPM/CNAPP)": r"cloud security|\bcspm\b|\bcnapp\b|\bcwpp\b",
    },
    "Network security": {
        "Firewalls": r"firewall", "Palo Alto": r"palo alto", "Fortinet": r"fortinet|fortigate",
        "IDS / IPS": r"\bids\b|\bips\b|intrusion (detection|prevention)", "Zero Trust": r"zero trust",
        "TCP/IP & networking": r"tcp/ip|networking|network protocols",
    },
    "Identity & access": {
        "IAM": r"\biam\b|identity and access", "Active Directory": r"active directory|\bentra\b",
        "PAM / CyberArk": r"\bpam\b|privileged access|cyberark", "SSO / SAML / OAuth": r"\bsso\b|\bsaml\b|oauth|openid",
        "Okta": r"\bokta\b",
    },
    "AppSec & DevSecOps": {
        "DevSecOps / CI/CD": r"devsecops|ci ?/ ?cd", "SAST / DAST": r"\bsast\b|\bdast\b|static analysis",
        "Secure code review": r"code review|secure coding", "Threat modeling": r"threat model",
    },
    "Frameworks & GRC": {
        "MITRE ATT&CK": r"mitre|att&ck", "NIST": r"\bnist\b", "ISO 27001": r"iso ?27001|iso/iec 27001",
        "SOC 2": r"\bsoc ?2\b", "PCI DSS": r"pci", "GDPR / privacy": r"gdpr|privacy", "Risk assessment": r"risk (assessment|management)",
        "CIS Controls": r"\bcis (controls|benchmarks?)\b", "NCA / NESA (Gulf)": r"\bnca\b|\bnesa\b|\bsama\b",
    },
    "OT / ICS": {"ICS / SCADA / OT": r"\bics\b|scada|\bot security|operational technology", "IEC 62443": r"62443"},
    "Programming & OS": {
        "Python": r"python", "PowerShell": r"powershell", "Bash / shell": r"\bbash\b|shell script",
        "Go": r"golang", "SQL / KQL": r"\bsql\b|\bkql\b", "JavaScript": r"javascript|typescript",
        "Linux": r"linux", "Windows": r"windows",
    },
    "Certifications": {
        "CISSP": r"cissp", "CISM": r"\bcism\b", "CISA": r"\bcisa\b", "OSCP": r"\boscp\b|\bose[pd]\b|\bosw[ea]\b",
        "CEH": r"\bceh\b|certified ethical hacker", "Security+": r"security\+|sec\+", "GIAC": r"giac|\bg(cih|cia|cfa|pen|sec|rem|cfe)\b",
        "CCSP": r"\bccsp\b", "AWS / Azure security cert": r"aws certified security|az-500|sc-200",
    },
}
_SKILL_RE = [(cat, name, re.compile(rx)) for cat, group in SKILLS.items() for name, rx in group.items()]

# YOUR skills, using the names from SKILLS above. Jobs asking for these score higher,
# and the Skills tab marks them "you have". Edit to match your CV.
MY_SKILLS = [
    "SIEM", "Splunk", "Microsoft Sentinel", "SOC", "Incident response", "Threat hunting",
    "EDR / XDR", "MITRE ATT&CK", "NIST", "ISO 27001", "Penetration testing", "Burp Suite",
    "OWASP", "Python", "Linux", "AWS", "Azure", "Vulnerability management", "Firewalls",
    "Security+", "CEH",
]

# LinkedIn search results have no description; open each new job's page to read it.
LINKEDIN_DETAILS = True
LINKEDIN_DETAIL_LIMIT = 250   # new job pages per run (cached afterwards, so this only bites on the first run)

REQUEST_DELAY = 0.5  # seconds between requests, be polite
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) job-scraper/1.0"

# ─────────────────────────── HELPERS ───────────────────────────


FAILED_REQUESTS = [0]  # failures in the current source, shown in the dashboard's coverage panel


def fetch(url, data=None, headers=None, delay=REQUEST_DELAY, retries=1):
    """GET/POST with a timeout and one retry. Returns the body text, or None on failure."""
    req = urllib.request.Request(url, data=data, headers={"User-Agent": UA, **(headers or {})})
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read().decode("utf-8", errors="replace")
        except OSError as e:  # URLError, HTTPError, socket timeouts, SSL errors
            if attempt == retries or getattr(e, "code", 0) in (401, 403, 404, 422):
                print(f"  ! {url} -> {e}", file=sys.stderr)
                FAILED_REQUESTS[0] += 1
                return None
            time.sleep(3)
        finally:
            time.sleep(delay)


def fetch_json(url, body=None):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    text = fetch(url, data, headers)
    try:
        return json.loads(text) if text else None
    except ValueError:
        print(f"  ! {url} -> not JSON", file=sys.stderr)
        return None


def fetch_text(url, delay=REQUEST_DELAY):
    return fetch(url, delay=delay) or ""


def first(pattern, text):
    m = re.search(pattern, text, re.S)
    return strip_html(m.group(1)) if m else ""


def strip_html(text):
    text = html.unescape(text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def any_match(patterns, text):
    return [p for p in patterns if re.search(p, text, re.I)]


def job(title, company, location, apply_url, source, description="", posted="",
        remote=None, link_type="direct"):
    return {
        "title": (title or "").strip(),
        "company": (company or "").strip(),
        "location": (location or "").strip(),
        "remote": remote,
        "apply_url": apply_url,
        "link_type": link_type,
        "source": source,
        "posted": (posted or "")[:10],
        "description": strip_html(description),
    }

# ─────────────────────────── SOURCES ───────────────────────────


def from_greenhouse(slug):
    data = fetch_json(f"https://boards-api.greenhouse.io/v1/boards/{slug}/jobs?content=true")
    for j in (data or {}).get("jobs", []):
        yield job(j.get("title"), slug, (j.get("location") or {}).get("name"),
                  j.get("absolute_url"), "greenhouse", j.get("content"), j.get("updated_at"))


def from_lever(slug):
    data = fetch_json(f"https://api.lever.co/v0/postings/{slug}?mode=json")
    if not isinstance(data, list):
        return
    for j in data:
        cats = j.get("categories") or {}
        posted = ""
        if j.get("createdAt"):
            posted = date.fromtimestamp(j["createdAt"] / 1000).isoformat()
        yield job(j.get("text"), slug, cats.get("location"),
                  j.get("applyUrl") or j.get("hostedUrl"), "lever",
                  j.get("descriptionPlain", "") + " " + j.get("additionalPlain", ""),
                  posted, remote=(j.get("workplaceType") == "remote") or None)


def from_ashby(slug):
    data = fetch_json(f"https://api.ashbyhq.com/posting-api/job-board/{slug}")
    for j in (data or {}).get("jobs", []):
        yield job(j.get("title"), slug, j.get("location"),
                  j.get("applyUrl") or j.get("jobUrl"), "ashby",
                  j.get("descriptionPlain") or j.get("descriptionHtml"),
                  j.get("publishedAt"), remote=j.get("isRemote") or None)


def from_workday(cfg):
    tenant, wd, site = cfg
    base = f"https://{tenant}.{wd}.myworkdayjobs.com"
    api = f"{base}/wday/cxs/{tenant}/{site}"
    seen = set()
    for term in WORKDAY_SEARCH:
        offset = 0
        while True:
            data = fetch_json(f"{api}/jobs", {"appliedFacets": {}, "limit": 20,
                                              "offset": offset, "searchText": term})
            postings = (data or {}).get("jobPostings") or []
            for p in postings:
                path = p.get("externalPath")
                if not path or path in seen or not is_security_title(p.get("title", "")):
                    continue
                seen.add(path)
                # Detail call gives the full location list + description.
                info = (fetch_json(f"{api}{path}") or {}).get("jobPostingInfo") or {}
                locs = [info.get("location") or p.get("locationsText", "")]
                locs += info.get("additionalLocations") or []
                yield job(p.get("title"), tenant, " | ".join(l for l in locs if l),
                          info.get("externalUrl") or f"{base}/{site}{path}", "workday",
                          info.get("jobDescription"), info.get("startDate"),
                          remote=("remote" in (info.get("remoteType") or "").lower()) or None)
            offset += 20
            if not postings or offset >= (data or {}).get("total", 0):
                break


def from_bayt():
    for country in BAYT_COUNTRIES:
        for q in BAYT_QUERIES:
            for page in (1, 2):
                url = f"https://www.bayt.com/en/{country}/jobs/{q}-jobs/"
                page_html = fetch_text(url + (f"?page={page}" if page > 1 else ""))
                blocks = page_html.split("<li data-js-job")[1:]
                if not blocks:
                    break
                for b in blocks:
                    href = first(r'<h2[^>]*>\s*<a[^>]*href="([^"]+)"', b)
                    if not href:
                        continue
                    salary = first(r'jb-label-salary">(.*?)</dt>', b)
                    exp = first(r'jb-label-careerlevel">(.*?)</dt>', b)
                    summary = first(r'jb-descr[^>]*>(.*?)</div>', b).replace("Summary:", "").strip()
                    yield job(first(r"<h2[^>]*>\s*<a[^>]*>(.*?)</a>", b),
                              first(r'job-company-location-wrapper">\s*<div>\s*<a[^>]*>(.*?)</a>', b),
                              first(r'jb-label-location[^>]*>(.*?)</dt>', b),
                              "https://www.bayt.com" + href, "bayt",
                              " | ".join(x for x in (salary, exp, summary) if x),
                              link_type="listing")


def from_gulftalent():
    for q in GULFTALENT_QUERIES:
        kw = urllib.parse.quote(q)
        for offset in range(0, 100, 25):
            data = fetch_json(
                "https://www.gulftalent.com/api/jobs/search?config%5Bfilters%5D=DISABLED"
                f"&config%5BisDynamicSearchV2%5D=true&filters%5Bsearch_keyword%5D={kw}"
                f"&include_scraped=1&limit=25&offset={offset}&search_keyword={kw}"
                "&search_order=r&version=2")
            rows = ((data or {}).get("results") or {}).get("data") or []
            for j in rows:
                posted = ""
                if j.get("posted_date_ts"):
                    posted = date.fromtimestamp(j["posted_date_ts"]).isoformat()
                yield job(j.get("title"), j.get("company_name"), j.get("location"),
                          "https://www.gulftalent.com" + j.get("link", ""), "gulftalent",
                          j.get("industry_name", ""), posted,
                          remote=bool(j.get("is_remote")) or None, link_type="listing")
            if len(rows) < 25:
                break


def from_linkedin():
    for loc in LINKEDIN_LOCATIONS:
        for q in LINKEDIN_QUERIES:
            for page in range(LINKEDIN_PAGES):
                url = ("https://www.linkedin.com/jobs-guest/jobs/api/seeMoreJobPostings/search"
                       f"?keywords={urllib.parse.quote(q)}&location={urllib.parse.quote(loc)}"
                       f"&f_TPR=r2592000&start={page * 10}")  # posted in last 30 days
                page_html = fetch_text(url, delay=LINKEDIN_DELAY)
                cards = page_html.split("<li>")[1:]
                if not cards:
                    break
                for c in cards:
                    link = first(r'base-card__full-link[^>]*href="([^"?]+)', c)
                    if not link:
                        continue
                    yield job(first(r'base-search-card__title">(.*?)</h3>', c),
                              first(r'base-search-card__subtitle">(.*?)</h4>', c),
                              first(r'job-search-card__location">(.*?)</span>', c),
                              link, "linkedin", "", first(r'datetime="([^"]+)"', c),
                              link_type="listing")


def linkedin_description(url):
    m = re.search(r"-(\d{6,})/?$", url) or re.search(r"/view/(\d+)", url)
    if not m:
        return ""
    page = fetch_text(f"https://www.linkedin.com/jobs-guest/jobs/api/jobPosting/{m.group(1)}",
                      delay=LINKEDIN_DELAY)
    return first(r'show-more-less-html__markup[^>]*>(.*?)</div>', page)


def from_remotive():
    for term in ["security", "cyber", "soc analyst", "penetration"]:
        q = urllib.parse.quote(term)
        data = fetch_json(f"https://remotive.com/api/remote-jobs?search={q}")
        for j in (data or {}).get("jobs", []):
            yield job(j.get("title"), j.get("company_name"), j.get("candidate_required_location"),
                      j.get("url"), "remotive", j.get("description"), j.get("publication_date"),
                      remote=True, link_type="listing")


def from_remoteok():
    data = fetch_json("https://remoteok.com/api?tag=security")
    for j in (data or [])[1:]:  # first item is a legal notice
        yield job(j.get("position"), j.get("company"), j.get("location"),
                  j.get("apply_url") or j.get("url"), "remoteok", j.get("description"),
                  j.get("date"), remote=True, link_type="listing")


def from_jobicy():
    for tag in ["security", "cybersecurity"]:
        data = fetch_json(f"https://jobicy.com/api/v2/remote-jobs?count=100&tag={tag}")
        for j in (data or {}).get("jobs", []):
            yield job(j.get("jobTitle"), j.get("companyName"), j.get("jobGeo"),
                      j.get("url"), "jobicy", j.get("jobDescription"), j.get("pubDate"),
                      remote=True, link_type="listing")

# ─────────────────────────── FILTER & SCORE ───────────────────────────


def is_security_title(title):
    t = f" {title.lower()} "
    return any(k in t for k in TITLE_KEYWORDS) and not any(x in t for x in TITLE_EXCLUDE)


def enrich(j):
    """Return the job with flags + score, or None if it should be dropped."""
    if not j["apply_url"] or not is_security_title(j["title"]):
        return None

    loc = j["location"].lower()
    desc = j["description"].lower()
    is_remote = bool(j["remote"]) or any(w in loc for w in REMOTE_WORDS)
    target = next((name for name, rx in _COUNTRY_RE if rx.search(loc)), "")

    if not is_remote and not target:
        return None

    restricted = [r for r in REMOTE_RESTRICTED if r in loc or r in desc] if is_remote else []
    relocation = any_match(RELOCATION_PATTERNS, desc)
    no_sponsor = any_match(NO_SPONSOR_PATTERNS, desc)
    languages = any_match(LANGUAGE_PATTERNS, desc)
    citizens_only = any_match(RESTRICTED_PATTERNS, j["title"].lower() + " " + desc)
    found = [name for _, name, rx in _SKILL_RE if rx.search(j["title"].lower() + " " + desc)]
    mine = [s for s in found if s in MY_SKILLS]

    score = len(mine) * 2
    score += 10 if relocation and not no_sponsor else 0
    score += 5 if is_remote and not restricted else 0
    score -= 15 if no_sponsor else 0
    score -= 10 if languages else 0
    score -= 10 if restricted else 0
    score -= 30 if citizens_only else 0

    j.update({
        "work_type": "remote" if is_remote else "onsite",
        "target_country": target,
        "relocation_or_visa": "yes" if relocation else "",
        "no_sponsorship": "yes" if no_sponsor else "",
        "other_language": ", ".join(languages),
        "citizens_only": "yes" if citizens_only else "",
        "remote_restricted": ", ".join(restricted),
        "matched_skills": ", ".join(mine),
        "skills": ", ".join(found),
        "has_description": "yes" if len(desc) > 200 else "",
        "score": score,
    })
    return j

# ─────────────────────────── MAIN ───────────────────────────

COLUMNS = ["score", "title", "company", "work_type", "location", "target_country",
           "apply_url", "link_type", "relocation_or_visa", "no_sponsorship",
           "other_language", "citizens_only", "remote_restricted", "matched_skills", "skills",
           "has_description", "posted",
           "source", "first_seen", "status", "description"]


def load_existing(path):
    if not os.path.exists(path):
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        return {row["apply_url"]: row for row in csv.DictReader(f)}


def main():
    sources = (
        [("greenhouse", s, from_greenhouse) for s in GREENHOUSE]
        + [("lever", s, from_lever) for s in LEVER]
        + [("ashby", s, from_ashby) for s in ASHBY]
        + [("workday", w, from_workday) for w in WORKDAY]
        + [("bayt", None, from_bayt), ("gulftalent", None, from_gulftalent)]
        + ([("linkedin", None, from_linkedin)] if LINKEDIN_LOCATIONS else [])
        + [("remotive", None, from_remotive), ("remoteok", None, from_remoteok),
           ("jobicy", None, from_jobicy)]
    )

    existing = load_existing(OUTPUT_CSV)
    today = date.today().isoformat()
    results = {}
    source_stats = []
    details_fetched = [0]

    def fill_description(j):
        """LinkedIn cards have no description: reuse the one saved last run, else fetch it."""
        if j["source"] != "linkedin" or j["description"] or not LINKEDIN_DETAILS:
            return j
        desc = existing.get(j["apply_url"], {}).get("description", "")
        if not desc and details_fetched[0] < LINKEDIN_DETAIL_LIMIT:
            details_fetched[0] += 1
            desc = linkedin_description(j["apply_url"])
        if desc:
            j["description"] = desc
            j = enrich(j) or j
        return j

    unknown = [s for s in MY_SKILLS if s not in {n for _, n, _ in _SKILL_RE}]
    if unknown:
        print(f"! MY_SKILLS names not in SKILLS (ignored): {unknown}", file=sys.stderr)

    for name, slug, fn in sources:
        label = slug[0] if isinstance(slug, tuple) else slug
        print(f"→ {name}{' / ' + label if label else ''}")
        count = 0
        FAILED_REQUESTS[0] = 0
        crashed = False
        try:
            for raw in (fn(slug) if slug else fn()):
                j = enrich(raw)
                if not j or j["apply_url"] in results:
                    continue
                j = fill_description(j)
                old = existing.get(j["apply_url"], {})
                j["first_seen"] = old.get("first_seen", today)
                j["status"] = old.get("status", "new")  # keep your manual status edits
                j["description"] = j["description"][:3000]
                results[j["apply_url"]] = j
                count += 1
        except Exception as e:  # one broken source must not kill the whole run
            print(f"  ! {name} failed: {e!r}", file=sys.stderr)
            crashed = True
        print(f"   kept {count}")
        source_stats.append({"source": name, "company": label or "", "kept": count,
                             "failed_requests": FAILED_REQUESTS[0], "crashed": crashed})

    # Keep jobs you've already touched even if they disappeared from the feed.
    for url, row in existing.items():
        if url not in results and row.get("status") not in ("", "new"):
            results[url] = row

    rows = sorted(results.values(), key=lambda r: int(r.get("score") or 0), reverse=True)
    os.makedirs(os.path.dirname(OUTPUT_CSV) or ".", exist_ok=True)
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        slim = [{k: r.get(k, "") for k in COLUMNS if k != "description"}
                | {"description": (r.get("description") or "")[:400]} for r in rows]
        coverage = {
            "countries": list(TARGET_COUNTRIES),
            "board_countries": {  # which job boards search each country directly
                "bayt": [c.replace("-", " ").title().replace("Uae", "UAE") for c in BAYT_COUNTRIES],
                "gulftalent": ["Qatar", "UAE", "Saudi Arabia", "Bahrain", "Kuwait", "Oman"],
                "linkedin": [l.replace("United Arab Emirates", "UAE") for l in LINKEDIN_LOCATIONS],
            },
            "sources": source_stats,
        }
        skills_meta = {"categories": {cat: list(group) for cat, group in SKILLS.items()},
                       "mine": [s for s in MY_SKILLS if any(s in g for g in SKILLS.values())]}
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "coverage": coverage, "skills": skills_meta, "jobs": slim}, f, ensure_ascii=False)

    new = sum(1 for r in rows if r.get("first_seen") == today)
    print(f"\nSaved {len(rows)} jobs to {OUTPUT_CSV} ({new} new today).")


if __name__ == "__main__":
    main()
