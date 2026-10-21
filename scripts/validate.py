#!/usr/bin/env python3
import json
import re
from datetime import datetime, timezone
from pathlib import Path
p=Path(__file__).resolve().parents[1]/"data/intelligence.json"
if not p.exists():
    print("No snapshot checked in yet; initial scheduled refresh will create one.")
    raise SystemExit(0)
data=json.loads(p.read_text(encoding="utf-8"))
assert data["schema"]==1
assert datetime.fromisoformat(data["generatedAt"].replace("Z","+00:00")).tzinfo
assert isinstance(data["vulnerabilities"],list) and len(data["vulnerabilities"])>=100
ids=set()
for row in data["vulnerabilities"]:
    assert re.fullmatch(r"CVE-\d{4}-\d{4,}",row["id"])
    assert row["id"] not in ids
    ids.add(row["id"])
    assert isinstance(row["inKEV"],bool)
    for key,maxval in (("cvss",10),("epss",1)):
        val=row.get(key)
        assert val is None or (isinstance(val,(int,float)) and 0<=val<=maxval)
    if row["inKEV"]: assert "CISA KEV" in row["source"]
for item in data.get("articles",[])+data.get("advisories",[]):
    assert item["url"].startswith("https://")
for item in data.get("indicators",[]):
    assert item["evidence"].startswith("https://urlhaus.abuse.ch/")
print("Validated",len(ids),"unique CVEs")
