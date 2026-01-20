from flask import Flask, render_template, request, jsonify
import requests
import feedparser
from datetime import datetime, timezone
import time
import hashlib
import os

# Optional OpenAI (AI explain feature)
from openai import OpenAI

app = Flask(__name__)

# ----------------------------
# CONFIG
# ----------------------------
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
NEWS_RSS = "https://www.bleepingcomputer.com/feed/"

HEADERS = {"User-Agent": "TriageHub/3.0 (Security Intelligence Project)"}

# Cache to avoid hammering external sources
CACHE = {
    "ts": 0,
    "ttl": 300,  # seconds (5 minutes)
    "items": []
}

# ----------------------------
# OPENAI (OPTIONAL)
# ----------------------------
_openai_client = None
if os.environ.get("OPENAI_API_KEY"):
    try:
        _openai_client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    except Exception as e:
        print("OpenAI init error:", e)
        _openai_client = None

# ----------------------------
# HELPERS
# ----------------------------
def iso_date(dt: datetime) -> str:
    """Return YYYY-MM-DD in UTC."""
    if not dt:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d")

def safe_lower(x):
    return (x or "").lower()

def sha1_id(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8")).hexdigest()[:12]

def infer_os(text_blob: str):
    """Best-effort OS inference from text."""
    text = safe_lower(text_blob)
    mapping = {
        "Windows": ["windows", "microsoft", ".exe", "active directory", "outlook", "mssql", "rdp", "powershell"],
        "MacOS": ["macos", "apple", "safari", "dmg", "plist", "m1", "m2", "iphone", "ios"],
        "Linux": ["linux", "ubuntu", "debian", "kernel", "bash", "elf", "ssh", "sudo", "apache", "nginx"],
        "Network": ["cisco", "fortinet", "palo alto", "vpn", "firewall", "router", "switch"],
    }
    found = [os_name for os_name, keys in mapping.items() if any(k in text for k in keys)]
    return found if found else ["Cross-Platform"]

def get_so_what(vendor: str, product: str, category: str):
    """Simple triage: who cares + what to do."""
    v = safe_lower(vendor)
    p = safe_lower(product)
    blob = f"{v} {p} {safe_lower(category)}"

    if any(x in blob for x in ["microsoft", "windows", "active directory", "exchange", "outlook"]):
        who = "Windows Admins / Endpoint Teams"
        action = "Verify patch status; prioritize exposed systems first; monitor for exploit attempts."
    elif any(x in blob for x in ["cisco", "fortinet", "palo alto", "vpn", "firewall"]):
        who = "Network Security / Edge Admins"
        action = "Prioritize edge patching; review VPN/Firewall logs for unusual auth/outbound behavior."
    elif any(x in blob for x in ["linux", "apache", "nginx", "kernel", "ssh"]):
        who = "Web App / Cloud Engineers"
        action = "Patch public-facing servers; audit configs; rotate credentials if compromise suspected."
    elif category in ["Malware", "Phishing"]:
        who = "SOC / Blue Team"
        action = "Block indicators (URL/DNS/IP); hunt for matches in proxy/DNS/email logs; brief users if phishing."
    else:
        who = "IT Operations"
        action = "Review advisory; validate exposure; apply fixes and monitor relevant logs."
    return {"who": who, "action": action}

def parse_any_date(date_str: str):
    """
    Parse common formats into YYYY-MM-DD when possible.
    If it's already YYYY-MM-DD, return it.
    """
    if not date_str:
        return ""
    s = date_str.strip()
    # common case already normalized
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        return s

    # try a few known patterns
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(s, fmt)
            return iso_date(dt.replace(tzinfo=timezone.utc))
        except Exception:
            pass
    return s[:10]  # fallback (best effort)

def to_timestamp(date_str: str) -> int:
    """Convert YYYY-MM-DD into an integer timestamp for sorting. Best-effort fallback."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0

def score_item(item: dict) -> int:
    """
    Simple urgency score.
    - CISA KEV starts high because it’s exploited-in-the-wild.
    - Malware/Phishing from URLhaus high.
    - News moderate.
    """
    base = 0
    source = item.get("source", "")
    category = item.get("category", "")
    tech = safe_lower(item.get("tech", ""))

    if source == "CISA KEV":
        base += 90
    elif source == "URLhaus":
        base += 70
    elif source == "BleepingComputer":
        base += 45

    if category == "Vulnerability":
        base += 20
    elif category == "Malware":
        base += 25
    elif category == "Phishing":
        base += 20
    elif category == "Incident":
        base += 15

    # extra boosts for common high-stakes areas
    if any(x in tech for x in ["vpn", "firewall", "exchange", "active directory", "rdp"]):
        base += 10

    return base

# ----------------------------
# INGESTORS (3 SOURCES)
# ----------------------------
def fetch_cisa_kev():
    """
    CISA KEV: official exploited vulnerabilities list.
    """
    items = []
    try:
        res = requests.get(CISA_URL, headers=HEADERS, timeout=15)
        data = res.json().get("vulnerabilities", [])
        for v in data:
            cve = v.get("cveID")
            vendor = v.get("vendorProject", "") or "Unknown"
            product = v.get("product", "") or "Unknown"
            title = v.get("vulnerabilityName") or cve or "CISA KEV item"
            desc = v.get("shortDescription") or ""
            date_added = parse_any_date(v.get("dateAdded", ""))

            triage = get_so_what(vendor, product, "Vulnerability")
            target_os = infer_os(f"{title} {desc} {vendor} {product}")

            item = {
                "id": cve or f"CISA-{sha1_id(title + desc)}",
                "source": "CISA KEV",
                "category": "Vulnerability",
                "label": "Exploit in the wild",
                "title": title,
                "desc": desc,
                "tech": f"{vendor} {product}".strip(),
                "vendor": vendor,
                "product": product,
                "target_os": target_os,
                "who": triage["who"],
                "action": triage["action"],
                "date": date_added,
                "ts": to_timestamp(date_added),
                "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else None,
                "is_new": False,  # you can compute this later if you want
            }
            item["score"] = score_item(item)
            items.append(item)
    except Exception as e:
        print("CISA error:", e)

    return items

def fetch_urlhaus_recent():
    """
    URLhaus: live malware/phishing URLs.
    """
    items = []
    try:
        res = requests.get(URLHAUS_URL, headers=HEADERS, timeout=15)
        data = res.json().get("urls", []) or []
        for u in data:
            threat = u.get("threat") or ""
            category = "Malware" if threat == "malware_download" else "Phishing"
            url = u.get("url") or ""
            host = u.get("host") or ""
            tags = u.get("tags") or []
            date_added = parse_any_date((u.get("date_added") or "").split(" ")[0])

            # stable unique id
            uid = u.get("id")
            item_id = f"URLH-{uid}" if uid else f"URLH-{sha1_id(url)}"

            triage = get_so_what("URLhaus", host, category)
            target_os = infer_os(f"{threat} {host} {' '.join(tags)}")

            title = f"Active {threat.replace('_',' ')}: {url[:60]}..." if url else "Active URLhaus hit"
            desc = f"Host: {host} | Tags: {', '.join(tags) if tags else 'none'}"

            item = {
                "id": item_id,
                "source": "URLhaus",
                "category": category,
                "label": "Live indicator",
                "title": title,
                "desc": desc,
                "tech": host,
                "vendor": "URLhaus",
                "product": host,
                "target_os": target_os,
                "who": triage["who"],
                "action": "Block URL/DNS; hunt in proxy/DNS/email logs; monitor for related IOCs.",
                "date": date_added,
                "ts": to_timestamp(date_added),
                "link": url,
                "nvd_url": None,
                "is_new": True,
            }
            item["score"] = score_item(item)
            items.append(item)
    except Exception as e:
        print("URLhaus error:", e)

    return items

def fetch_bleepingcomputer_rss():
    """
    BleepingComputer RSS: incidents/news.
    Uses the real published time from the feed when available.
    """
    items = []
    try:
        feed = feedparser.parse(NEWS_RSS)
        for entry in (feed.entries or [])[:40]:
            title = entry.get("title", "BleepingComputer item")
            summary = entry.get("summary", "") or entry.get("description", "")
            link = entry.get("link", "")

            # published date (real)
            published_dt = None
            if entry.get("published_parsed"):
                published_dt = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
            elif entry.get("updated_parsed"):
                published_dt = datetime.fromtimestamp(time.mktime(entry.updated_parsed), tz=timezone.utc)
            date_pub = iso_date(published_dt) if published_dt else iso_date(datetime.now(timezone.utc))

            # stable unique ID for dedupe: use link hash (or title hash)
            item_id = f"NEWS-{sha1_id(link or title)}"

            triage = get_so_what("BleepingComputer", "", "Incident")
            target_os = infer_os(f"{title} {summary}")

            item = {
                "id": item_id,
                "source": "BleepingComputer",
                "category": "Incident",
                "label": "News / Incident",
                "title": title,
                "desc": (summary[:240] + "...") if len(summary) > 240 else summary,
                "tech": "News / Threat Intel",
                "vendor": "BleepingComputer",
                "product": "",
                "target_os": target_os,
                "who": triage["who"],
                "action": "Read the report; compare to internal telemetry; add relevant detections/blocks if applicable.",
                "date": date_pub,
                "ts": to_timestamp(date_pub),
                "link": link,
                "nvd_url": None,
                "is_new": False,
            }
            item["score"] = score_item(item)
            items.append(item)
    except Exception as e:
        print("RSS error:", e)

    return items

# ----------------------------
# NORMALIZE + DEDUPE + CACHE
# ----------------------------
def refresh_feed():
    now = time.time()
    if CACHE["items"] and (now - CACHE["ts"] < CACHE["ttl"]):
        return CACHE["items"]

    all_items = []
    all_items.extend(fetch_cisa_kev())
    all_items.extend(fetch_urlhaus_recent())
    all_items.extend(fetch_bleepingcomputer_rss())

    # Dedupe by ID (keep the highest score if collision)
    best_by_id = {}
    for it in all_items:
        if not it.get("id"):
            continue
        existing = best_by_id.get(it["id"])
        if not existing or it.get("score", 0) > existing.get("score", 0):
            best_by_id[it["id"]] = it

    merged = list(best_by_id.values())

    # Default sort: newest first (you can override per request)
    merged.sort(key=lambda x: x.get("ts", 0), reverse=True)

    CACHE["items"] = merged
    CACHE["ts"] = now
    return merged

# ----------------------------
# FILTERING / SORTING
# ----------------------------
def apply_filters(items, q=None, source=None, category=None, os_name=None, vendor=None):
    def match(it):
        if source and safe_lower(it.get("source")) != safe_lower(source):
            return False
        if category and safe_lower(it.get("category")) != safe_lower(category):
            return False
        if os_name:
            os_list = it.get("target_os", []) or []
            if not any(safe_lower(os_name) == safe_lower(x) for x in os_list):
                return False
        if vendor:
            blob = f"{it.get('vendor','')} {it.get('product','')} {it.get('tech','')}"
            if safe_lower(vendor) not in safe_lower(blob):
                return False
        if q:
            blob = f"{it.get('id','')} {it.get('title','')} {it.get('desc','')} {it.get('tech','')} {it.get('vendor','')} {it.get('product','')}"
            if safe_lower(q) not in safe_lower(blob):
                return False
        return True

    return [it for it in items if match(it)]

def sort_items(items, sort_mode="newest"):
    if sort_mode == "urgent":
        return sorted(items, key=lambda x: (x.get("score", 0), x.get("ts", 0)), reverse=True)
    # newest
    return sorted(items, key=lambda x: x.get("ts", 0), reverse=True)

# ----------------------------
# AI EXPLAIN (NEW)
# ----------------------------
@app.route("/api/ai_explain", methods=["POST"])
def api_ai_explain():
    """
    POST JSON with a threat object (the same shape your UI uses).
    Returns a short explanation meant for humans.
    """
    if not _openai_client:
        return jsonify({
            "ok": False,
            "explanation": "AI is disabled. Set OPENAI_API_KEY in your environment to enable this feature."
        }), 200

    data = request.get_json(force=True) or {}

    # Keep it tight and safe: explain, don’t provide attack steps.
    prompt = f"""
Explain this security item in simple terms for a practitioner.

Output format:
- What it is (1–2 lines)
- Who should care (1 line)
- What to do now (2–4 bullets)
- Why it matters (1 line)
Rules:
- Be calm, direct, non-alarmist.
- Do NOT give exploitation instructions.
- Keep it under ~140 words.

Threat item:
ID: {data.get("id")}
Category: {data.get("category")}
Source: {data.get("source")}
Title: {data.get("title")}
Description: {data.get("desc")}
Tech: {data.get("tech")}
Target OS: {", ".join(data.get("target_os") or [])}
Suggested action: {data.get("action")}
"""

    try:
        resp = _openai_client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            max_tokens=220,
            messages=[
                {"role": "system", "content": "You are a helpful cybersecurity analyst. Be practical and avoid sensationalism."},
                {"role": "user", "content": prompt},
            ],
        )
        explanation = (resp.choices[0].message.content or "").strip()
        return jsonify({"ok": True, "explanation": explanation}), 200

    except Exception as e:
        return jsonify({
            "ok": False,
            "explanation": f"AI error: {str(e)}"
        }), 200

# ----------------------------
# ROUTES
# ----------------------------
@app.route("/")
def index():
    items = refresh_feed()

    # Query params (optional)
    q = request.args.get("q")
    source = request.args.get("source")      # CISA KEV | URLhaus | BleepingComputer
    category = request.args.get("category")  # Vulnerability | Malware | Phishing | Incident
    os_name = request.args.get("os")         # Windows | MacOS | Linux | Network | Cross-Platform
    vendor = request.args.get("vendor")
    sort_mode = request.args.get("sort", "newest")  # newest | urgent
    limit = int(request.args.get("limit", "300"))

    filtered = apply_filters(items, q=q, source=source, category=category, os_name=os_name, vendor=vendor)
    filtered = sort_items(filtered, sort_mode=sort_mode)[:limit]

    # If you’re using the Alpine UI that expects `threats`
    return render_template("index.html", threats=filtered, preselect=None)

@app.route("/threat/<item_id>")
def detail(item_id):
    items = refresh_feed()
    threat = next((x for x in items if x.get("id") == item_id), None)
    return render_template("index.html", threats=items, preselect=threat)

@app.route("/api/threats")
def api_threats():
    items = refresh_feed()

    q = request.args.get("q")
    source = request.args.get("source")
    category = request.args.get("category")
    os_name = request.args.get("os")
    vendor = request.args.get("vendor")
    sort_mode = request.args.get("sort", "newest")
    limit = int(request.args.get("limit", "300"))

    filtered = apply_filters(items, q=q, source=source, category=category, os_name=os_name, vendor=vendor)
    filtered = sort_items(filtered, sort_mode=sort_mode)[:limit]
    return jsonify(filtered)

@app.route("/api/meta")
def api_meta():
    """Small helper endpoint so the UI can populate filter dropdowns."""
    items = refresh_feed()

    sources = sorted(list({x.get("source") for x in items if x.get("source")}))
    categories = sorted(list({x.get("category") for x in items if x.get("category")}))
    os_values = sorted(list({os_name for x in items for os_name in (x.get("target_os") or [])}))
    return jsonify({
        "sources": sources,
        "categories": categories,
        "oses": os_values
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
