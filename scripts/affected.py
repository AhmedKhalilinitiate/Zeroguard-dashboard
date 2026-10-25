"""Source-backed affected systems for NVD CPE, CISA CSAF, GHSA and KEV.

Never infer confirmed affected systems from vulnerability description or remediation
targets. A system whose status is unknown remains explicitly unknown.
"""
import re
from urllib.parse import unquote

VALID_SOURCES = {"NVD CPE", "CISA CSAF OT", "CISA CSAF IT", "GitHub Advisory (npm)", "GitHub Advisory (composer)", "CISA KEV"}
UNKNOWN = "Not identified in connected sources"

def short(value, max_length=200):
    return str(value or "").strip()[:max_length]

def clean_entries(entries, limit=24):
    output, seen = [], set()
    for entry in entries or []:
        if not isinstance(entry, dict): continue
        name = short(entry.get("name"))
        if not name or name in ("*", "-", "Unknown"): continue
        src = short(entry.get("source"), 70)
        if src not in VALID_SOURCES: continue
        version = short(entry.get("version"), 170)
        key=(name.lower(),version.lower(),src)
        if key in seen:continue
        seen.add(key)
        url = short(entry.get("url"), 500)
        if url and not url.startswith("https://"):url=""
        output.append({"name":name,"version":version or "Version not specified",
                       "source":src,"url":url,"status":"affected"})
        if len(output)>=limit:break
    return output

def combine(existing, incoming):
    return clean_entries([*(existing or []),*(incoming or [])])

def parts(criteria):
    """Handle CPE 2.3 colon delimiters with escaped colons."""
    return re.split(r"(?<!\\):", str(criteria or ""))

def nvd_configurations(configurations, cve_id):
    results = []
    url = "https://nvd.nist.gov/vuln/detail/" + str(cve_id)
    def visit(node):
        if not isinstance(node,dict):return
        for obj in node.get("cpeMatch") or []:
            if not isinstance(obj,dict) or obj.get("vulnerable") is not True:continue
            cpe=parts(obj.get("criteria"))
            if len(cpe)<6 or cpe[:2]!=["cpe","2.3"]:continue
            kind,vendor,product,version=cpe[2:6]
            if kind not in ("a","o","h") or product in ("*", "-", ""):continue
            friendly=lambda val:val.replace("\\:",":").replace("_"," ").replace("\\","").strip()
            name=(friendly(vendor)+" "+friendly(product)).strip() if vendor not in ("*","-") else friendly(product)
            ranges=[]
            for key,label in (("versionStartIncluding",">="),("versionStartExcluding",">"),("versionEndIncluding","<="),("versionEndExcluding","<")):
                if obj.get(key):ranges.append(label+short(obj[key],70))
            ver=", ".join(ranges) if ranges else ("Version "+friendly(version) if version not in ("*","-","") else "Version not specified")
            results.append({"name":name,"version":ver,"source":"NVD CPE","url":url})
        for child in node.get("nodes") or []:
            visit(child)
    for config in configurations or []:
        if isinstance(config,dict):visit(config)
    return clean_entries(results)

def ghsa_versions(advisory, url=None):
    out=[]
    for issue in (advisory.get("vulnerabilities") or []):
        if not isinstance(issue,dict):continue
        package=issue.get("package") or {}
        name=short(package.get("name"))
        ecosystem=short(package.get("ecosystem")).lower()
        if not name or ecosystem not in ("npm","composer"):continue
        ver=short(issue.get("vulnerable_version_range"),170) or "Version not specified"
        out.append({"name":ecosystem+": "+name,"version":ver,
                    "source":"GitHub Advisory ("+ecosystem+")",
                    "url":url or advisory.get("html_url") or ""})
    return clean_entries(out)

def csaf_affected(vulnerability, product_names, source, url):
    """Only affected or first/last affected statuses. Fixed/non-affected != vulnerable."""
    status=vulnerability.get("product_status") or {}
    ids=[]
    for key in ("known_affected","first_affected","last_affected"):
        ids.extend(status.get(key) or [])
    results=[]
    for pid in dict.fromkeys(ids):
        name=product_names.get(pid)
        if name:
            results.append({"name":name,"version":"See advisory for version applicability",
                            "source":source,"url":url})
    return clean_entries(results)

def finalize(record):
    current=clean_entries(record.get("affectedSystems"))
    # KEV product families are source claims, although exact versions might not be provided.
    if record.get("inKEV") and record.get("product"):
        vendor=short(record.get("vendor"))
        product=short(record.get("product"))
        generic=("unknown","unspecified","multiple products","various","")
        if product.lower() not in generic and vendor.lower() != product.lower():
            name=(vendor+" "+product).strip()
        else:name=product
        if name.lower() not in generic:
            current=combine(current,[{"name":name,"version":"Affected versions not specified in KEV",
                           "source":"CISA KEV",
                           "url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}])
    record["affectedSystems"]=current
    record["affectedSystemLabel"]=current[0]["name"] if current else UNKNOWN
    record["affectedSystemCount"]=len(current)
    # No inference from "npm" or "composer" alone: an ecosystem is not a product.
    return record
