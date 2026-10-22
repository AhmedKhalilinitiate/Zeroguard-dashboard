import unittest
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import ingest

class IncrementalFeedTests(unittest.TestCase):
    def test_ghsa_merges_valid_cve_without_kev(self):
        records={}
        ingest.merge_ghsa(records,[{"id":"CVE-2026-98765","description":"Example npm issue","date":"2026-10-22","ecosystem":"npm","source":"GitHub Advisory (npm)","reference":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc"}])
        self.assertIn("CVE-2026-98765", records)
        self.assertFalse(records["CVE-2026-98765"]["inKEV"])
        self.assertEqual(records["CVE-2026-98765"]["published"],"2026-10-22")
    def test_ipsum_validates_ip_and_reputation(self):
        sample=b"# heading\n8.8.8.8\t4\n192.168.0.1\t9\n999.0.0.1\t11\n1.2.3.4\t1\n9.9.9.9\t5\n"
        with patch.object(ingest, "fetch", return_value=sample):
            result=ingest.ipsum_indicators()
        self.assertEqual([x["value"] for x in result],["8.8.8.8","9.9.9.9"])
        self.assertEqual(result[0]["type"],"ip")
    def test_report_not_cve(self):
        data=[{"title":"Node.js critical security vulnerability patch released","source":"example","date":"2026-10-21","url":"https://example.org/a"},{"title":"PHP performance tips","source":"example","date":"2026-10-21","url":"https://example.org/b"}]
        result=ingest.reports_from_news(data)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["status"],"Reported; verify vendor advisory and CVE")
if __name__ == "__main__":
    unittest.main()
