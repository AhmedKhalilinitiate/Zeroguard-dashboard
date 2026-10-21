import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import csaf

BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/example.json"

class CISAAdvisoryTests(unittest.TestCase):
    def sample(self):
        return {
            "document":{"csaf_version":"2.0","title":"Example controller advisory",
              "tracking":{"id":"ICSA-26-001-01","current_release_date":"2026-10-20T00:00:00Z"}},
            "product_tree":{"full_product_names":[{"product_id":"p1","name":"Controller 5.0"}]},
            "vulnerabilities":[{"cve":"CVE-2026-12345",
                "notes":[{"category":"summary","text":"Example vulnerability"}],
                "remediations":[{"category":"mitigation","details":"Disable remote web access."},
                                {"category":"vendor_fix","details":"Upgrade firmware to 5.1.","url":"https://example.com/security","product_ids":["p1"]}],
                "scores":[{"cvss_v3":{"baseScore":8.8}}]}]}
    def test_prioritizes_verifiable_vendor_fix(self):
        article,changes=csaf.parse_advisory(self.sample(), BASE, "OT")
        self.assertEqual(changes[0]["remediation"]["details"],"Upgrade firmware to 5.1.")
        self.assertEqual(changes[0]["remediation"]["category"],"vendor_fix")
        self.assertEqual(changes[0]["products"],["Controller 5.0"])
        self.assertEqual(changes[0]["cvss"],8.8)
        self.assertEqual(article["cves"],["CVE-2026-12345"])
    def test_applies_fix_and_preserves_kev(self):
        records={"CVE-2026-12345":{"id":"CVE-2026-12345","inKEV":True,"kevAction":"Apply mitigation per CISA KEV","source":["CISA KEV"],"references":[],"cvss":None}}
        _,changes=csaf.parse_advisory(self.sample(), BASE, "OT")
        csaf.apply(records,changes,"OT")
        row=records["CVE-2026-12345"]
        self.assertEqual(row["action"],"Upgrade firmware to 5.1.")
        self.assertEqual(row["kevAction"],"Apply mitigation per CISA KEV")
    def test_no_fake_vendor_fix(self):
        obj=self.sample();obj["vulnerabilities"][0]["remediations"]=[]
        _,changes=csaf.parse_advisory(obj,BASE,"OT")
        records={"CVE-2026-12345":{"id":"CVE-2026-12345","inKEV":True,"action":"Generic CISA requirement","source":["CISA KEV"],"references":[]}}
        csaf.apply(records,changes,"OT")
        self.assertEqual(records["CVE-2026-12345"]["action"],"")
    def test_rejects_foreign_feed_urls(self):
        feed={"feed":{"entry":[{"content":{"src":"https://evil.example.com/test.json"}},{"content":{"src":BASE},"updated":"2026-10-20"}]}}
        entries=csaf.feed_entries(feed,"OT",20)
        self.assertEqual(len(entries),1)
    def test_latest_empty_not_ok(self):
        with self.assertRaises(ValueError):
            csaf.parse_advisory({"document":{"csaf_version":"1.0"}},BASE,"OT")

if __name__ == "__main__":
    unittest.main()
