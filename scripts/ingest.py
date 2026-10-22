#!/usr/bin/env python3
"""ZeroGuard v6: authenticated-origin feed collection and conservative normalization.
Runs on GitHub Actions. Uses Python's standard library only.
"""
import csv
import ipaddress
import csaf
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
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "SANS ISC": "https://isc.sans.edu/rssfeed.xml",
}
STATS = {}
IP_SUM = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
GHSA_API = "https://api.github.com/advisories"

def fetch(url, max_bytes=8_000_000, retries=1, timeout=12):
    # Sources are fixed, trusted HTTPS destinations. No user-supplied URLs or proxies.
    if not url.startswith("https://"):
        raise ValueError("HTTPS required")
    for attempt in range(retries + 1):
        try:
            headers = {"User-Agent": UA, "Accept": "application/json,application/xml,text/xml,text/csv,*/*"}
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=timeout) as resp:
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
        "action": "", "kevAction": "", "date": stamp(c.get("published")), "modified": stamp(c.get("lastModified")),
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
            "kevAction": str(v.get("requiredAction") or "")[:1500],
            "action": (old.get("remediation") or {}).get("details", ""),
            "date": stamp(v.get("dateAdded")), "dueDate": stamp(v.get("dueDate")),
            "ransomwareUse": str(v.get("knownRansomwareCampaignUse") or "Unknown"),
            "inKEV": True, "exploitedKnown": True, "remediationStatus": "unknown",
            "source": sorted(set(old.get("source", [])) | {"CISA KEV"}),
            "cvss": old.get("cvss"), "epss": old.get("epss"),
            "remediation": old.get("remediation"),
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
              "resultsPerPage": 250}
    visited = 0
    for page in range(4):
        params["startIndex"] = page * 250
        url = base + "?" + urllib.parse.urlencode(params)
        data = json.loads(fetch(url, retries=0, max_bytes=3_000_000, timeout=28).decode('utf-8-sig'))
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
        if (page + 1) * 250 >= data.get("totalResults", 0) or not batch: break
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
    STATS["rss"] = {"ok": ok > 0, "sources": ok, "totalSources": len(RSS), "scope": "Independent security publisher RSS; official CISA uses CSAF"}
    return articles[:200], advisories[:100]

def ipsum_indicators():
    """Reputation signals from public IPsum; not proof that an IP is malicious."""
    source = IP_SUM
    lines = fetch(source, max_bytes=4_000_000).decode("utf-8-sig").splitlines()
    indicators = []
    for line in lines:
        if not line or line.startswith("#"):
            continue
        columns = line.split()
        if len(columns) < 2:
            continue
        try:
            addr = ipaddress.ip_address(columns[0])
            appearances = int(columns[1])
        except (ValueError, TypeError):
            continue
        # Feed aggregated blocklists with >=3 independent appearances.
        if addr.version != 4 or not addr.is_global or appearances < 3:
            continue
        indicators.append({
            "type": "ip", "value": str(addr), "date": NOW.date().isoformat(),
            "threat": "Listed on " + str(appearances) + " aggregated blocklists",
            "confidence": "unverified reputation", "status": "reported",
            "source": "IPsum / stamparm", "evidence": "https://github.com/stamparm/ipsum"
        })
        if len(indicators) >= 200:
            break
    if not indicators:
        raise ValueError("IPsum parsed no public high-agreement IP indicators")
    STATS["ioc_ipsum"] = {"ok":True,"count":len(indicators),"url":"https://github.com/stamparm/ipsum",
                          "scope":"Aggregated IP blocklist signals; not independently confirmed IOCs"}
    return indicators


def github_advisories():
    """Capture newly published npm/Packagist advisories including pending-CVE GHSAs."""
    reports = []
    cve_rows = []
    seen = set()
    for ecosystem in ("npm", "composer"):
        source = GHSA_API + "?" + urllib.parse.urlencode({
            "ecosystem": ecosystem, "per_page": "100", "sort": "published", "direction": "desc"
        })
        try:
            results = fetch_json(source)
            if not isinstance(results, list):
                raise ValueError("GitHub advisory endpoint returned invalid data")
            count = 0
            for issue in results:
                if issue.get("withdrawn_at") or issue.get("type") not in ("reviewed", "unreviewed", None):
                    continue
                published = stamp(issue.get("published_at"))
                if published and published < (NOW - timedelta(days=30)).date().isoformat():
                    continue
                ghsa = str(issue.get("ghsa_id") or "").strip()
                url = str(issue.get("html_url") or "")
                if not ghsa.startswith("GHSA-") or not url.startswith("https://github.com/advisories/GHSA-"):
                    continue
                if ghsa in seen:
                    continue
                seen.add(ghsa)
                title = str(issue.get("summary") or ghsa)[:280]
                description = str(issue.get("description") or "")[:1200]
                cveid = str(issue.get("cve_id") or "").upper()
                report = {"title":title,"source":"GitHub Advisory (" + ecosystem + ")",
                    "date": published, "url":url, "advisoryId":ghsa,
                    "cves":[cveid] if CVE.fullmatch(cveid) else [],
                    "status":"published advisory" if CVE.fullmatch(cveid) else "GHSA; CVE not assigned",
                    "ecosystem":ecosystem, "reportedZeroDay":False}
                reports.append(report)
                if CVE.fullmatch(cveid):
                    cve_rows.append({
                        "id":cveid,"description":description or title,
                        "date":published,"source":report["source"],"reference":url,
                        "ecosystem":ecosystem
                    })
                count += 1
            STATS["ghsa_" + ecosystem] = {"ok":True,"count":count,"url":"https://github.com/advisories",
                "scope":"Published GitHub security advisories for " + ecosystem}
        except Exception as e:
            STATS["ghsa_" + ecosystem] = {"ok":False,"error":str(e)[:160],
                "url":"https://github.com/advisories"}
    reports.sort(key=lambda r:r["date"],reverse=True)
    return reports[:180],cve_rows


def merge_ghsa(records, rows):
    for item in rows:
        cid=item["id"]
        if cid not in records:
            records[cid] = {
                "id":cid,"vendor":"","product":item["ecosystem"],
                "description":item["description"],"date":item["date"],
                "published":item["date"],"source":[item["source"]],
                "references":[item["reference"]],"action":"",
                "kevAction":"","cvss":None,"vector":"","epss":None,
                "percentile":None,"inKEV":False,"exploitedKnown":False,
                "dueDate":"","ransomwareUse":"","cwe":[],
                "remediationStatus":"unknown"
            }
        else:
            rec=records[cid]
            rec["source"]=sorted(set(rec.get("source",[]))|{item["source"]})
            refs=rec.get("references") or []
            if item["reference"] not in refs:
                refs.append(item["reference"])
            rec["references"]=refs[:15]
            if not rec.get("description"): rec["description"]=item["description"]
            if not rec.get("published"): rec["published"]=item["date"]


def reports_from_news(articles):
    """Rumors remain reports, never created CVEs or proven exploitation."""
    reports=[]
    watched=re.compile(r"\bnode(?:\.?\s*js|js)?\b|\bphp\b|\bnpm\b|\bpackagist\b",re.I)
    security=re.compile(r"vulnerab|security|flaw|zero.day|0.day|exploit|cve-|patch|rce|remote.code|supply.chain|malware",re.I)
    for entry in articles:
        title=str(entry.get("title") or "")
        if watched.search(title) and security.search(title):
            reports.append({**entry,"status":"Reported; verify vendor advisory and CVE",
                "ecosystem":"node/php watch"})
    return reports[:80]

def main():
    previous = load_previous()
    # Preserve previously sourced non-KEV CVEs. The previous implementation
    # removed all of them on EVERY refresh, making new disclosures disappear.
    # Retain recently discovered records for an explicit rolling 120-day window.
    cutoff = (NOW - timedelta(days=120)).date().isoformat()
    records = {k:v for k,v in previous.items()
               if v.get("inKEV") or
                  "CISA CSAF IT" in (v.get("source") or []) or
                  "CISA CSAF OT" in (v.get("source") or []) or
                  (v.get("published") or v.get("date") or "") >= cutoff}
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
        csaf_articles, csaf_advisories, csaf_health = csaf.collect(records, fetch_json)
        STATS.update(csaf_health)
    except Exception as err:
        STATS["csaf"] = {"ok": False, "error": str(err)[:160]}
        csaf_articles, csaf_advisories = [], []
    try:
        ghsa_reports, ghsa_rows = github_advisories()
        merge_ghsa(records, ghsa_rows)
    except Exception as e:
        STATS["ghsa"]={"ok":False,"error":str(e)[:150]}
        ghsa_reports=[]
    try:
        epss(records)
    except Exception as e:
        STATS["epss"] = {"ok":False, "error":str(e)[:180]}
        print("EPSS unavailable:",e, file=sys.stderr)
    try: articles, advisories = rss()
    except Exception as e:
        STATS["rss"] = {"ok":False, "error":str(e)[:180]}
        articles, advisories = [], []
    articles = csaf_articles + articles
    advisories = csaf_advisories + advisories
    articles.sort(key=lambda r: r.get("date") or "", reverse=True)
    reports = ghsa_reports + reports_from_news(articles)
    reports.sort(key=lambda r: r.get("date") or "", reverse=True)
    # Deduplicate by evidence URL, not title: unrelated reports can share headlines.
    seen_urls=set()
    reports=[r for r in reports if r.get("url") and
             (r["url"] not in seen_urls and not seen_urls.add(r["url"]))]

    advisories.sort(key=lambda r: r.get("date") or "", reverse=True)
    try:
        indicators=ipsum_indicators()
    except Exception as e:
        STATS["ioc_ipsum"]={"ok":False,"error":str(e)[:180]}
        indicators=[]
        print("IPsum unavailable:",e,file=sys.stderr)
    # Never wipe existing IOCs on a temporary source outage; mark cached clearly.
    if not indicators:
        try:
            snapshot=json.loads((DATA/"intelligence.json").read_text(encoding="utf-8"))
            indicators=snapshot.get("indicators") or []
            if indicators: STATS["ioc_cache"]={"ok":True,"count":len(indicators),
                "scope":"Previous snapshot, age/freshness unknown until next successful IOC ingest"}
        except (OSError,ValueError):
            pass

    for v in records.values():
        # CVE publication date differs from the date CISA added an older CVE to KEV.
        v["displayDate"] = v.get("published") or v.get("date") or ""
        v["kevAction"] = v.get("kevAction") or (v.get("action", "") if "remediation" not in v and v.get("inKEV") else "")
        verified = v.get("remediation") or {}
        v["action"] = verified.get("details", "")
        v["actionStatus"] = "vendor-specific" if verified.get("details") else "not independently verified"
        v["category"] = category(v.get("vendor",""), v.get("product",""), v.get("description",""))
    sorted_rows = sorted(records.values(), key=lambda v:(v.get("displayDate") or "", v["id"]), reverse=True)
    generated = NOW.isoformat(timespec="seconds").replace("+00:00","Z")
    output = {"schema": 1, "generatedAt": generated,
              "sources": STATS, "vulnerabilities": sorted_rows,
              "articles": articles[:230], "advisories": advisories[:100],
              "reports": reports[:200], "indicators": indicators}
    temp = DATA / "intelligence.tmp"
    temp.write_text(json.dumps(output, ensure_ascii=False, separators=(",",":")), encoding="utf-8")
    temp.replace(DATA / "intelligence.json")
    (DATA / "status.json").write_text(json.dumps({"generatedAt":generated, "records":len(sorted_rows), "sources":STATS},indent=2),encoding="utf-8")
    print(json.dumps({"generatedAt":generated, "vulnerabilities":len(sorted_rows),
                      "news":len(articles), "icsAdvisories":len(advisories),
                      "indicators":len(indicators), "sources":STATS},indent=2))
if __name__ == "__main__":
    main()
