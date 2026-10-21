# ZeroGuard Pro v6 — Threat Intelligence Operations

A responsive, source-attributed, security intelligence dashboard that updates **automatically** using scheduled GitHub Actions. Built by Ahmed Khalil.

## What works

- **CISA KEV:** validated catalog of vulnerabilities with confirmed real-world exploitation, due dates, vendor remediation instructions and ransomware-campaign indication.
- **NVD:** incrementally ingests recently modified CVEs and attaches official CVSS/vector scores when available. NVD's API may rate-limit requests; failures are visible in Source health.
- **FIRST EPSS:** attaches real 30-day exploitation probabilities, where available, in batches.
- **OT/ICS:** groups relevant vulnerabilities using conservative keywords and separately displays CISA ICS RSS advisories. Classification is indicative, not a formal determination of affected equipment.
- **Threat news:** sourced, dated headlines from CISA and selected security publishers.
- **IOC intelligence:** URLhaus's public recent malicious URL feed. Dangerous URLs are rendered as inert text rather than clickable links.
- **Web UI:** KPI overview, top risk prioritization, live source freshness and health, searchable/paginated CVE tables, filtering/sorting, CVE detail with evidence links, local bookmarks, CSV export, responsive mobile navigation.
- **Unscored stays unscored:** no fabricated CVSS, EPSS, ATT&CK, zero-day status, actor attribution or patch deployment claims.
- **Scheduled updates:** `.github/workflows/update-intelligence.yml` runs **every six hours** plus manual dispatch. The browser fetches the published snapshot every 15 minutes while open.

## Deployment

1. In GitHub **Settings → Pages**, select **GitHub Actions** as the build/deployment source.
2. The existing `Deploy ZeroGuard to GitHub Pages` workflow deploys `main` on every push.
3. Under **Actions → Update verified threat intelligence**, select **Run workflow** to generate the initial snapshot immediately; subsequent refreshes are scheduled every six hours.
4. Actions needs **Read and write permissions** for `GITHUB_TOKEN` to commit `data/intelligence.json` and `data/status.json`. On protected branches, the collector's push may be blocked; configure an approved automation branch/PR flow instead.
5. Open the deployed GitHub Pages URL. Until the first successful ingestion, the UI gives a clear unavailable-data message instead of inventing sample results.

All feeds use public HTTPS endpoints. **No API credentials are required**, but source availability and NVD rate limits affect how much enrichment is available.

## Development and tests

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
python scripts/ingest.py
python scripts/validate.py
node tests/integrity.test.cjs
node tests/app.test.cjs
python -m http.server 8080
```

Then open `http://localhost:8080`. A scheduled snapshot is committed at `data/intelligence.json`; the data collector needs internet access. The front end uses plain HTML/CSS/JS with **no frontend runtime dependencies**.

## Architecture

```
GitHub Actions (every 6h)
       ├── CISA KEV JSON (required)
       ├── NVD CVE v2 REST (bounded incremental ingestion)
       ├── FIRST EPSS API (batched)
       ├── Security publisher RSS / CISA ICS
       └── abuse.ch URLhaus recent CSV
                 ↓
        Validated JSON snapshot
          data/intelligence.json
                 ↓
         GitHub Pages static site
          index.html + styles.css + app.js
                 ↓
       Browser (polls every 15 min)
```

**Data quality:** A failed required KEV retrieval exits without overwriting the last snapshot. Optional source failures are recorded in `sources`. NVD CVSS and EPSS enrichment from the prior snapshot may persist after a failed update; these are the latest *successfully retrieved* values, not automatically current. Historical snapshots beyond the current one are not retained. The collector is intentionally bounded (at most 12,000 recently modified NVD records per run, plus the KEV catalog) and does **not** claim exhaustive coverage of all NVD disclosures.

**Zero-day evidence:** Headlines that contain “zero-day” are labeled *reported mentions*. No headline is treated as proof of zero-day exploitation. KEV membership confirms exploitation, not when exploitation started relative to patch availability.

**Threat actor profiles and MITRE ATT&CK:** Not shown because no reliable evidence-based attribution feed is connected. They must not be inferred from CVE identifiers.

**Limitations:** This is a threat-intelligence **triage** interface, not an asset scanner, EDR, SIEM, patch deployment agent, complete vulnerability inventory or guaranteed near-real-time alerting service. For enterprise use, implement asset-aware matching, authenticated audit logs, RBAC, and a controlled ingestion service. GitHub schedule delays and upstream rate limits are expected; always check Source health before acting.

## Troubleshooting

- **Data unavailable:** run the update workflow and inspect its logs. Pages deployment follows a successful snapshot commit to main.
- **Stale snapshot:** check the update workflow, repository write permissions and KEV endpoint access.
- **EPSS/NVD not available:** inspect source errors in the Source health page; the app keeps missing fields explicitly unknown.
- **Local testing:** serve via HTTP, not `file://`, because the browser must fetch `data/intelligence.json`.
