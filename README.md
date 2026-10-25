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


## Asset exposure assessment (v7)

Select **Asset exposure** in the left navigation. The workspace imports asset inventories **locally inside the browser**: no asset data is transmitted to ZeroGuard or committed to GitHub.

Supported formats:
- CSV with `name,version,vendor,purl,cpe,host,criticality,exposure` (only `name`, PURL or CPE is necessary; a download template is available).
- JSON arrays or `{"assets":[...]}`.
- CycloneDX JSON software bills of materials (`components`).
- SPDX JSON documents (`packages`).

Import up to 5,000 assets / 5 MB, or add assets individually. Select **Run assessment**, then filter findings or download a CSV report. Imported data remains in memory and is cleared by page reload or **Clear inventory**.

### Interpretation and safety
- **Version match** means a source-backed package identity/PURL or comparable CPE identity matched an affected-version expression. It is a triage *candidate*, not a proof of exploitability.
- **Needs verification** means the product appears related but version or applicability evidence is insufficient.
- Only limited numeric version conditions are evaluated (`<`, `<=`, `>`, `>=`, `=`). Unsupported pre-release, ecosystem-specific or complex constraints stay unknown. Complex NVD CPE Boolean applicability and environment-specific conditions require manual verification.
- The matcher does not inspect live hosts, detect runtime configurations, authenticate to assets, or guarantee exhaustive CVE coverage. Missing findings never imply the asset is secure.
- Priority is a **local heuristic** informed by CISA KEV, CVSS, EPSS, asset criticality and exposure. It is not an authoritative risk score.

Tests: `node tests/matcher.test.cjs` and `node tests/browser.test.cjs` (the latter needs `jsdom@26`).

## Electrical substations: native Excel inventories

In **Asset exposure**, import multiple `.xlsx` files directly from the customer questionnaire used by the two Riyadh substation inventories. Files are processed in memory inside the browser; they are never uploaded to GitHub or a server.

- Reads *Substation Name*, *Asset Type*, *Asset Qty.*, *Vendor Name*, *Model Number*, *Firmware Number*, *Panel Name*, and the room-section headings from worksheets.
- Supports multiple files at once (each row is an equipment line item; quantity is retained, **not** interpreted as individual serial-numbered devices).
- Automatically selects **OT substations: vendor + model research screening** for these files.
- **Model-referenced lead** means a manufacturer AND distinctive model reference occurs in the CVE's affected-system or description data; without firmware and applicability evidence it is not a confirmed impacted device.
- **Vendor-only lead** is a broader investigative lead: same manufacturer, but no reliable model correlation. Do NOT treat as vulnerability on the inventoried system.
- With missing manufacturer/model, no automatic matching is claimed. Source files in this format may leave firmware entirely blank.
- Users can switch to *Installed asset/version assessment* when evidence supports specific firmware matching; this is still conservative and incomplete for complex industrial CPE conditions.

Native Excel parsing uses built-in browser ZIP decompression and XML parsing, requires a recent modern browser, supports ordinary OOXML `.xlsx` (not password-protected or legacy `.xls`), and does not evaluate formulas. If an Excel file is not recognized, use the downloadable CSV template or pre-normalize it.

Security operations must verify affected models, firmware, exposure, vendor bulletins and change windows prior to remediation. OT searches never send packets to substation controllers or other devices.

## Evidence-first, nonintrusive OT investigation

Use **Asset exposure → OT substations: vendor + model research screening** and import the local substation Excel files. ZeroGuard now provides two **independent** dimensions: source-evidence applicability confidence and **investigation priority**, based only on information present in the vulnerability source and *explicitly provided* criticality/exposure context. No firmware inference, live controller connection, automatic patching, or scanning.

The **OT investigation and evidence register** provides missing asset-evidence counts, OT owner, review due dates, recorded evidence IDs, investigation status and six compensating-control categories. Controls default to *Not assessed*. **Evidence verified** requires a non-empty supporting reference; no actual validation of that evidence is claimed. Investigations and assets remain in browser memory, not on GitHub. Export **assessment JSON** to preserve and later restore the work, or **investigation CSV** for review. An unexported assessment disappears on page reload. Store downloaded reports under your organization's authorized OT document-handling rules.

Supporting guidance: NIST SP 800-82 Rev.3 and CISA's OT asset inventory/foundations guidance emphasize safety, passive data sources, operational constraints and cautious change control. Sources and applicability must still be confirmed by an authorized OT engineer.

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
