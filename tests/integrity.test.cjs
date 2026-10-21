const assert = require('node:assert/strict');
const fs = require('node:fs');
const html = fs.readFileSync('index.html','utf8');
function expect(text) { assert.ok(html.includes(text), 'Missing expected behavior: '+text); }
expect("const ZERO_DAY_WATCH = []");
expect("const OT_SUPPLEMENTAL = []");
expect("const IOC_DATABASE = []");
expect("const STATIC_NEWS_FALLBACK = []");
expect("source: 'CISA KEV'");
expect("score: null");
expect("epss: null");
expect("remediationStatus: 'unknown'");
expect("function safeExternalUrl(value)");
expect("return row.map(csvCell).join(',')");
assert.doesNotMatch(html, /Math\.abs\(hash\).*% 100/);
assert.doesNotMatch(html, /ZERO_DAY_WATCH = \[\s*\{/);
assert.doesNotMatch(html, /OT_SUPPLEMENTAL = \[\s*\{/);
const script = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(script, 'Inline application script must exist');
new Function(script[1]); // Parse JavaScript without executing browser code.
console.log('ZeroGuard integrity and JavaScript syntax checks passed.');
