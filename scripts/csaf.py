"""Official CISA CSAF IT/OT advisory ingester.

Uses CISA's own GitHub-hosted machine-readable advisories, not the
cisa.gov RSS endpoints that return HTTP 403 to GitHub-hosted runners.
CSAF is the OASIS Common Security Advisory Framework 2.0.
"""
import re
from datetime import datetime
from urllib.parse import urlparse

BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/"
OFFICIAL_REPO = "https://github.com/cisagov/CSAF"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
PRIORITIES = {"vendor_fix": 0, "workaround": 1, "mitigation": 2, "none_available": 3}

def date_only(value):
    return str(value or "")[:10] if re.match(r"^\d{4}-\d\d-\d\d", str(value or "")) else ""

def https_url(url):
    try:
        u = urlparse(str(url or ""))
        return u.geturl() if u.scheme == "https" and bool(u.netloc) else ""
    except (TypeError, ValueError):
        return ""

def feed_path(kind):
    if kind not in ("OT", "IT"):
        raise ValueError("Unknown CSAF category")
    return BASE + kind + "/white/cisa-csaf-" + kind.lower() + "-feed-tlp-white.json"

def feed_entries(feed, kind, limit):
    entries = (feed.get("feed") or {}).get("entry") or []
    if not isinstance(entries, list):
        raise ValueError("Unexpected CSAF feed format")
    prefix = BASE + kind + "/white/"
    verified = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        url = (item.get("content") or {}).get("src") or ""
        # Never follow external paths injected into upstream feed entries.
        if not isinstance(url, str) or not url.startswith(prefix) or not url.endswith(".json"):
            continue
        if "/../" in url or "?" in url or "#" in url:
            continue
        verified.append(item)
    verified.sort(key=lambda e: (e.get("updated") or e.get("published") or "", e.get("id") or ""), reverse=True)
    return verified[:limit]

def product_names(doc):
    result = {}
    for product in (doc.get("product_tree") or {}).get("full_product_names") or []:
        if isinstance(product, dict) and product.get("product_id"):
            result[product["product_id"]] = str(product.get("name") or "")
    return result

def parse_advisory(raw, source_url, kind):
    if not source_url.startswith(BASE + kind + "/white/"):
        raise ValueError("Untrusted advisory location")
    document = raw.get("document") or {}
    if document.get("csaf_version") != "2.0":
        raise ValueError("Not a CSAF 2.0 advisory")
    tracking = document.get("tracking") or {}
    advisory_id = str(tracking.get("id") or "")
    if not advisory_id:
        raise ValueError("Advisory missing id")
    title = str(document.get("title") or advisory_id)[:280]
    date = date_only(tracking.get("current_release_date") or tracking.get("initial_release_date"))
    web_url = ""
    for ref in document.get("references") or []:
        candidate = https_url(ref.get("url"))
        if candidate.startswith("https://www.cisa.gov/news-events/"):
            web_url = candidate
            break
    news = {"title": title, "url": web_url or source_url,
            "source": "CISA CSAF " + kind, "date": date,
            "advisoryId": advisory_id, "reportedZeroDay": False, "cves": []}
    names = product_names(raw)
    changes = []
    for v in raw.get("vulnerabilities") or []:
        cve = str(v.get("cve") or "").strip().upper()
        if not CVE_PATTERN.fullmatch(cve):
            continue
        desc = next((str(n.get("text") or "")[:1200] for n in v.get("notes") or []
                     if n.get("category") == "summary" and n.get("text")), "")
        candidates = []
        for rem in v.get("remediations") or []:
            cat = str(rem.get("category") or "")
            detail = str(rem.get("details") or "").strip()[:2000]
            if not detail or cat not in PRIORITIES:
                continue
            vendor_url = https_url(rem.get("url"))
            associated = [names[i] for i in rem.get("product_ids") or [] if i in names]
            candidates.append({
                "category": cat, "details": detail,
                "vendorUrl": vendor_url, "advisoryUrl": source_url,
                "source": "CISA CSAF " + kind, "updated": date,
                "products": associated[:12]
            })
        candidates.sort(key=lambda m: (PRIORITIES[m["category"]], -len(m["details"])))
        selected = candidates[0] if candidates else None
        cvss = None
        for entry in v.get("scores") or []:
            data = entry.get("cvss_v4") or entry.get("cvss_v3") or entry.get("cvss_v2") or {}
            try:
                n = float(data.get("baseScore"))
                if 0 <= n <= 10:
                    cvss = round(n, 1)
                    break
            except (TypeError, ValueError):
                pass
        news["cves"].append(cve)
        changes.append({"id": cve, "description": desc, "remediation": selected,
                        "cvss": cvss, "date": date, "source": "CISA CSAF " + kind,
                        "advisoryUrl": source_url, "products": (selected or {}).get("products") or []})
    news["cves"] = list(dict.fromkeys(news["cves"]))
    news["remediationCount"] = sum(1 for c in changes if c["remediation"])
    return news, changes

def apply(records, changes, kind):
    fixes = 0
    cvss_added = 0
    for item in changes:
        cid = item["id"]
        old = records.get(cid) or {}
        if not old:
            old = {"id": cid, "vendor": "", "product": "", "description": "",
                   "action": "", "kevAction": "", "cvss": None, "vector": "",
                   "epss": None, "percentile": None, "inKEV": False,
                   "exploitedKnown": False, "dueDate": "", "ransomwareUse": "",
                   "published": "", "modified": "", "cwe": [],
                   "references": [], "remediationStatus": "unknown", "source": []}
            records[cid] = old
        old["source"] = sorted(set(old.get("source") or []) | {item["source"]})
        if not old.get("description") and item["description"]:
            old["description"] = item["description"]
        if not old.get("date"):
            old["date"] = item["date"]
        if old.get("cvss") is None and item["cvss"] is not None:
            old["cvss"] = item["cvss"]
            cvss_added += 1
        if not old.get("product") and item.get("products"):
            old["product"] = ", ".join(item["products"])[:250]
        references = old.get("references") or []
        if item["advisoryUrl"] not in references:
            references.append(item["advisoryUrl"])
        old["references"] = references[:15]
        proposed = item["remediation"]
        prior = old.get("remediation")
        if proposed and (not prior or (proposed["updated"] or "") >= (prior.get("updated") or "")):
            old["remediation"] = proposed
            old["action"] = proposed["details"]
            fixes += 1
        else:
            # Old versions stored a generic CISA KEV requirement in "action".
            # Do not let it masquerade as verified vendor remediation.
            old["action"] = prior["details"] if prior and prior.get("details") else ""
    return fixes, cvss_added

def collect(records, fetch_json, max_ot=28, max_it=14):
    articles, advisories, health = [], [], {}
    for kind, limit in (("OT", max_ot), ("IT", max_it)):
        name = "csaf_CISA " + kind
        feed_url = feed_path(kind)
        try:
            feed = fetch_json(feed_url)
            items = feed_entries(feed, kind, limit)
            if not items:
                raise ValueError("CSAF feed has no valid entries")
            successes, failures, fixes, cvss_added = 0, 0, 0, 0
            for entry in items:
                source_url = entry["content"]["src"]
                try:
                    doc = fetch_json(source_url)
                    news, changes = parse_advisory(doc, source_url, kind)
                    count, enriched = apply(records, changes, kind)
                    fixes += count
                    cvss_added += enriched
                    articles.append(news)
                    if kind == "OT":
                        advisories.append(news)
                    successes += 1
                except Exception:
                    failures += 1
            if not successes:
                raise ValueError("No CISA CSAF documents could be fetched")
            health[name] = {"ok": True, "count": successes, "failedDocuments": failures,
                            "vendorActions": fixes, "cvssAdded": cvss_added,
                            "url": OFFICIAL_REPO,
                            "scope": "Latest public official CISA CSAF " + kind + " advisories"}
        except Exception as e:
            health[name] = {"ok": False, "error": str(e)[:160], "url": OFFICIAL_REPO}
    articles.sort(key=lambda v: v["date"], reverse=True)
    advisories.sort(key=lambda v: v["date"], reverse=True)
    return articles, advisories, health
