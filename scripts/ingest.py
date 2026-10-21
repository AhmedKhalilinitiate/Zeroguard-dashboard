#!/usr/bin/env python3
"""ZeroGuard v6: authenticated-origin feed collection and conservative normalization.
Runs on GitHub Actions. Uses Python's standard library only.
"""
import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
DATA.mkdir(exist_ok=True)
NOW = datetime.now(timezone.utc)
UA = "ZeroGuard-v6/1.0 (+https://github.com/AhmedKhalilinitiate/Zeroguard-dashboard)"
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
OT = ("siemens", "schneider electric", "rockwell", "allen-bradley", "honeywell",
      "yokogawa", "abb", "emerson", "moxa", "advantech", "phoenix contact",
      "omron", "mitsubishi electric", "ge vernova", "industrial", "scada", "plc",
      "modbus", "opc ua", "dnp3", "ics", "operational technology")
CONSUMER = ("android", "apple", "iphone", "ipad", "samsung mobile", "chromium",
            "chrome", "mozilla firefox", "safari", "pixel", "ios", "macos",
            "windows 11", "windows 10", "home router", "tp-link", "netgear")
RSS = {
    "CISA advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "CISA ICS": "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "SANS ISC": "https://isc.sans.edu/rssfeed.xml",
}
STATS = {}

def fetch(url, max_bytes=8_000_000, retries=1):
    # Sources are fixed, trusted HTTPS destinations. No user-supplied URLs or proxies.
    if not url.startswith("https://"):
        raise ValueError("HTTPS required")
    for attempt in range(retries + 1):
        try:
            headers = {"User-Agent": UA, "Accept": "application/json,application/xml,text/xml,text/csv,*/*"}
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=12) as resp:
                if resp.status != 200:
                    raise ValueError("HTTP " + str(resp.status))
                b = resp.read(max_bytes + 1)
                if len(b) > max_bytes:
                    raise ValueError("source too large")
                return b
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as err:
            if attempt == retries:
                raise
            time.sleep(2 + attempt * 3)
    raise RuntimeError("unreachable")

def fetch_json(url):
    return json.loads(fetch(url).decode("utf-8-sig"))

def stamp(value):
    if not value: return ""
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return ""

def score(value, max_value=10):
    try:
        v = float(value)
        return round(v, 4) if 0 <= v <= max_value else None
    except (TypeError, ValueError):
        return None

def category(vendor, product, description):
    s = (vendor + " " + product + " " + description).lower()
    if any(term in s for term in OT): return "ot"
    if any(term in s for term in CONSUMER): return "consumer"
    return "it"

def best_cvss(cve):
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for obj in metrics.get(key, []):
            if obj.get("type") == "Primary":
                d = obj.get("cvssData") or {}
                return score(d.get("baseScore")), str(d.get("vectorString") or "")
        for obj in metrics.get(key, []):
            d = obj.get("cvssData") or {}
            if score(d.get("baseScore")) is not None:
                return score(d.get("baseScore")), str(d.get("vectorString") or "")
    return None, ""

def english(descs):
    for d in descs or []:
        if d.get("lang") == "en": return str(d.get("value") or "")[:1200]
    return ""

def normalize_nvd(raw):
    c = raw.get("cve") or {}
    cid = str(c.get("id") or "")
    if not CVE.fullmatch(cid) or c.get("vulnStatus") in ("Rejected", "REJECT"): return None
    descriptions = english(c.get("descriptions"))
    # NVD doesn't always supply a reliable canonical product/vendor pair.
    weaknesses = [d.get("value","") for w in c.get("weaknesses", []) for d in w.get("description", []) if d.get("lang") == "en"]
    references = [r.get("url") for r in c.get("references", []) if str(r.get("url") or "").startswith("https://")][:6]
    cvss, vector = best_cvss(c)
    return {
        "id": cid, "vendor": "", "product": "", "description": descriptions,
        "action": "", "date": stamp(c.get("published")), "modified": stamp(c.get("lastModified")),
        "cvss": cvss, "vector": vector, "epss": None, "percentile": None,
        "inKEV": False, "exploitedKnown": False, "dueDate": "", "ransomwareUse": "",
        "cwe": weaknesses[:5], "references": references, "source": ["NVD"],
        "published": stamp(c.get("published")), "remediationStatus": "unknown"
    }

def load_previous():
    path = DATA / "intelligence.json"
    if not path.exists(): return {}
    try:
        previous = json.loads(path.read_text(encoding="utf-8"))
        return {v["id"]: v for v in previous.get("vulnerabilities", []) if CVE.fullmatch(v.get("id",""))}
    except (OSError, json.JSONDecodeError, KeyError):
        return {}

def kev(records):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    data = fetch_json(url)
    if not isinstance(data.get("vulnerabilities"), list) or not data["vulnerabilities"]:
        raise ValueError("CISA KEV payload invalid or empty")
    for v in data["vulnerabilities"]:
        cid = str(v.get("cveID") or "").upper()
        if not CVE.fullmatch(cid): continue
        old = records.get(cid) or {}
        records[cid] = {
            **old, "id": cid, "vendor": str(v.get("vendorProject") or ""),
            "product": str(v.get("product") or ""),
            "description": str(v.get("shortDescription") or old.get("description") or "")[:1200],
            "action": str(v.get("requiredAction") or "")[:1500],
            "date": stamp(v.get("dateAdded")), "dueDate": stamp(v.get("dueDate")),
            "ransomwareUse": str(v.get("knownRansomwareCampaignUse") or "Unknown"),
            "inKEV": True, "exploitedKnown": True, "remediationStatus": "unknown",
            "source": sorted(set(old.get("source", [])) | {"CISA KEV"}),
            "cvss": old.get("cvss"), "epss": old.get("epss"),
            "percentile": old.get("percentile"), "vector": old.get("vector",""),
            "cwe": old.get("cwe", []), "references": old.get("references", []),
            "modified": old.get("modified",""), "published": old.get("published","")
        }
    STATS["kev"] = {"ok": True, "count": len(data["vulnerabilities"]), "url": url}
    return len(data["vulnerabilities"])

def nvd(records):
    # Recent changes, not the entire universe of NVD records. Page using NVD's own totalResults.
    end = NOW
    days = max(1, min(int(os.getenv("NVD_DAYS","7")), 90))
    start = end - timedelta(days=days)
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
              "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
              "resultsPerPage": 2000}
    visited = 0
    for page in range(6):
        params["startIndex"] = page * 2000
        url = base + "?" + urllib.parse.urlencode(params)
        data = fetch_json(url)
        batch = data.get("vulnerabilities", [])
        for item in batch:
            row = normalize_nvd(item)
            if not row: continue
            cid = row["id"]
            old = records.get(cid)
            if old:
                for key in ("cvss", "vector", "modified", "published", "cwe", "references"):
                    if row.get(key) is not None and row.get(key) != "": old[key] = row[key]
                if not old.get("description"): old["description"] = row["description"]
                old["source"] = sorted(set(old.get("source", [])) | {"NVD"})
            else:
                records[cid] = row
            visited += 1
        if (page + 1) * 2000 >= data.get("totalResults", 0) or not batch: break
        time.sleep(6)
    STATS["nvd"] = {"ok": True, "count": visited, "scope": "Recently modified CVEs, past %d days" % days, "url": base}
    return visited

def epss(records):
    ids = sorted(records)
    count = 0
    for start in range(0, len(ids), 80):
        batch = ids[start:start+80]
        query = urllib.parse.urlencode({"cve": ",".join(batch), "limit": "100"})
        data = fetch_json("https://api.first.org/data/v1/epss?" + query)
        for row in data.get("data", []):
            item = records.get(row.get("cve"))
            if not item: continue
            item["epss"] = score(row.get("epss"), 1)
            item["percentile"] = score(row.get("percentile"), 1)
            if item["epss"] is not None: count += 1
        time.sleep(.25)
    STATS["epss"] = {"ok": True, "count": count, "url": "https://www.first.org/epss/"}

def pubdate(s):
    if not s: return ""
    try:
        import email.utils
        d = email.utils.parsedate_to_datetime(s)
        return d.astimezone(timezone.utc).date().isoformat()
    except (ValueError, TypeError):
        return stamp(s)

def gettext(root, label):
    for child in root:
        if child.tag.split("}")[-1].lower() == label.lower():
            return (child.text or "").strip()
    return ""

def rss():
    articles, advisories = [], []
    seen = set()
    ok = 0
    for name, url in RSS.items():
        try:
            xml = fetch(url, 4_000_000)
            root = ET.fromstring(xml)
            count = 0
            for item in root.iter():
                if item.tag.split("}")[-1] not in ("item", "entry"): continue
                title = gettext(item, "title")[:250]
                link = gettext(item, "link")
                if not link:
                    for x in item:
                        if x.tag.split("}")[-1] == "link" and x.get("href"):
                            link = x.get("href")
                            break
                if not title or not link.startswith("https://") or link in seen: continue
                seen.add(link)
                date = pubdate(gettext(item, "pubDate") or gettext(item, "published") or gettext(item, "updated"))
                record = {"title": title, "url": link, "source": name, "date": date,
                          "reportedZeroDay": bool(re.search(r"\bzero[\s-]?day\b|\b0day\b", title, re.I))}
                articles.append(record)
                if name == "CISA ICS": advisories.append(record)
                count += 1
                if count >= 75: break
            STATS["rss_" + name] = {"ok": True, "count": count, "url": url}
            ok += 1
        except Exception as err:
            STATS["rss_" + name] = {"ok": False, "error": str(err)[:150], "url": url}
    articles.sort(key=lambda r:r["date"], reverse=True)
    advisories.sort(key=lambda r:r["date"], reverse=True)
    STATS["rss"] = {"ok": ok > 0, "sources": ok, "totalSources": len(RSS)}
    return articles[:200], advisories[:100]

def urlhaus():
    source = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    raw = fetch(source, 7_000_000).decode("utf-8-sig", errors="replace")
    # The URLhaus CSV format includes comment lines; never fetch or follow reported malicious URLs.
    lines = (line for line in raw.splitlines() if line and not line.startswith("#"))
    indicators = []
    seen = set()
    for row in csv.reader(lines):
        # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
        if len(row) < 8: continue
        _, date, value, status, _, threat, tags, evidence = row[:8]
        if status != "online" or not value.startswith(("http://", "https://")): continue
        if value in seen: continue
        if not evidence.startswith("https://urlhaus.abuse.ch/"): continue
        seen.add(value)
        indicators.append({"type":"url", "value":value[:1200], "status":"reported online",
                           "date":stamp(date), "threat":threat[:100],
                           "tags":tags[:180], "source":"abuse.ch URLhaus", "evidence":evidence})
        if len(indicators) >= 100: break
    STATS["urlhaus"] = {"ok": True, "count": len(indicators), "url": source}
    return indicators

def main():
    previous = load_previous()
    records = {k:v for k,v in previous.items() if v.get("inKEV")}
    # No newly generated data can be published without a successfully validated KEV catalog.
    try:
        count = kev(records)
        if not count: raise RuntimeError("CISA KEV empty")
    except Exception as e:
        print("FATAL: official KEV unavailable; existing checked-in data preserved:",e,file=sys.stderr)
        sys.exit(2)
    try:
        nvd(records)
    except Exception as e:
        STATS["nvd"] = {"ok":False, "error":str(e)[:180]}
        print("NVD unavailable:",e, file=sys.stderr)
    try:
        epss(records)
    except Exception as e:
        STATS["epss"] = {"ok":False, "error":str(e)[:180]}
        print("EPSS unavailable:",e, file=sys.stderr)
    try: articles, advisories = rss()
    except Exception as e:
        STATS["rss"] = {"ok":False, "error":str(e)[:180]}
        articles, advisories = [], []
    try: indicators = urlhaus()
    except Exception as e:
        STATS["urlhaus"] = {"ok":False, "error":str(e)[:180]}
        indicators = []
        print("URLhaus unavailable:",e, file=sys.stderr)
    for v in records.values():
        v["category"] = category(v.get("vendor",""), v.get("product",""), v.get("description",""))
    sorted_rows = sorted(records.values(), key=lambda v:(v.get("date") or "", v["id"]), reverse=True)
    generated = NOW.isoformat(timespec="seconds").replace("+00:00","Z")
    output = {"schema": 1, "generatedAt": generated,
              "sources": STATS, "vulnerabilities": sorted_rows,
              "articles": articles, "advisories": advisories, "indicators": indicators}
    temp = DATA / "intelligence.tmp"
    temp.write_text(json.dumps(output, ensure_ascii=False, separators=(",",":")), encoding="utf-8")
    temp.replace(DATA / "intelligence.json")
    (DATA / "status.json").write_text(json.dumps({"generatedAt":generated, "records":len(sorted_rows), "sources":STATS},indent=2),encoding="utf-8")
    print(json.dumps({"generatedAt":generated, "vulnerabilities":len(sorted_rows),
                      "news":len(articles), "icsAdvisories":len(advisories),
                      "indicators":len(indicators), "sources":STATS},indent=2))
if __name__ == "__main__":
    main()
