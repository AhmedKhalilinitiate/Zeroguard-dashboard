# ZeroGuard Dashboard

ZeroGuard is a static, browser-based cybersecurity dashboard. This v5.4 change prioritizes **evidence integrity** over presenting inferred threat intelligence as facts.

## Verified data
- **CISA Known Exploited Vulnerabilities (KEV)**: the only vulnerability records ingested for the dashboard. KEV indicates documented exploitation, **not necessarily a zero-day**.
- Product, vendor, date added, recommended action and agency due date originate from KEV.
- **CVSS, EPSS, MITRE ATT&CK technique, actor attribution and remediation state** are currently **not enriched or verified**. They are deliberately unscored/unknown rather than generated using CVE-ID hashes.
- Historical zero-day examples, OT supplemental records, IOCs, and dated actor-activity claims from the previous version were unsourced. They have been disabled instead of silently presented as live.
- The OT/ICS tab uses heuristic categorization of KEV records. It is **not a comprehensive CISA ICS advisory feed**. Verify product applicability with official advisories.
- A zero count in an unconnected feed is **not evidence of no active threats**.

## Usage
Open `index.html` on a static host. The dashboard can be served by GitHub Pages with no secrets. Browser CORS restrictions may prevent direct CISA access; existing third-party CORS fallbacks are used if required, and their availability/integrity is not guaranteed. For operational use, replace these public proxies with a controlled, audited backend that fetches CISA and publishes provenance-preserving JSON.

The app loads Chart.js and fonts over the internet, and news RSS through third-party relays. News may be unavailable or cached; do not treat cached articles as current.

## Source integrity and next improvements
1. Add a server-side, scheduled ingestion pipeline for official NVD CVSS, FIRST EPSS and CISA ICS advisories. Validate schema, timestamp and per-record attribution.
2. Add a separately sourced vendor-advisory lifecycle: *fixed version released* vs *asset patched* are different claims.
3. Add per-record first-seen/updated timestamps and source links, retain evidence of changes.
4. Distinguish *confirmed exploitation*, *public PoC*, *zero-day at exploitation*, and *no evidence*. Never use KEV membership alone to assign zero-day.
5. Remove public CORS relay dependencies; configure a restrictive CSP and eliminate inline event handlers before enterprise deployment.

## Data privacy
Bookmarks and vulnerability cache stay in the browser's local storage/IndexedDB. Clearing the browser's data removes them.

## Security note
This is an intelligence triage aid, not a scanner, vulnerability management platform, or conclusive detection engine. Validate every advisory and remediation against your assets and vendor guidance before operational action.
