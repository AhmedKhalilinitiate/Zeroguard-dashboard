import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import ingest

class IngestionTests(unittest.TestCase):
    def test_cvss_primary(self):
        v={"cve":{"id":"CVE-2026-12345","descriptions":[{"lang":"en","value":"Example"}],
              "metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":7.8}},{"type":"Primary","cvssData":{"baseScore":9.8,"vectorString":"CVSS:3.1/X"}}]}}}
        self.assertEqual(ingest.normalize_nvd(v)["cvss"],9.8)
    def test_rejected_excluded(self):
        self.assertIsNone(ingest.normalize_nvd({"cve":{"id":"CVE-2026-12345","vulnStatus":"Rejected"}}))
    def test_bad_ids_excluded(self):
        self.assertIsNone(ingest.normalize_nvd({"cve":{"id":"NOT-A-CVE"}}))
    def test_missing_not_zero(self):
        self.assertIsNone(ingest.score(None))
        self.assertIsNone(ingest.score("not available"))
        self.assertIsNone(ingest.score(11))
        self.assertEqual(ingest.score("0.013",1),0.013)
    def test_categorization(self):
        self.assertEqual(ingest.category("Siemens","PLC","device"),"ot")
        self.assertEqual(ingest.category("Unknown","Chrome","Browser"),"consumer")
        self.assertEqual(ingest.category("Acme","Server","RCE"),"it")
    def test_date(self):
        self.assertEqual(ingest.stamp("2026-10-01T07:00:00Z"),"2026-10-01")
        self.assertEqual(ingest.stamp("bad"),"")
    def test_refuse_insecure_url(self):
        with self.assertRaises(ValueError): ingest.fetch("http://example.com")
if __name__=="__main__": unittest.main()
