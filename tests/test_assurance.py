import sys
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ingest

class AssuranceTests(unittest.TestCase):
    def setUp(self):
        ingest.STATS.clear()

    def test_partial_and_resume(self):
        def fetch(url, **kwargs):
            from urllib.parse import urlparse, parse_qs
            offset = int(parse_qs(urlparse(url).query)["startIndex"][0])
            return json.dumps({"totalResults": 1001, "startIndex": offset,
                "vulnerabilities": [{"cve": {"id": f"CVE-2025-{i+1000}"}} for i in range(offset, min(offset+250,1001))]}).encode()
        with tempfile.TemporaryDirectory() as tmp, patch.object(ingest, "DATA", Path(tmp)), patch.object(ingest, "fetch", side_effect=fetch), patch.object(ingest.time, "sleep"):
            records = {}
            ingest.nvd(records)
            self.assertFalse(ingest.STATS["nvd"]["ok"])
            self.assertEqual(ingest.STATS["nvd"]["cursor"]["offset"], 1000)
            (Path(tmp)/"intelligence.json").write_text(json.dumps({"sources": ingest.STATS}))
            ingest.nvd(records)
            self.assertTrue(ingest.STATS["nvd"]["ok"])
            self.assertEqual(len(records), 1001)
            self.assertIsNone(ingest.STATS["nvd"]["cursor"])

    def test_kev_removal(self):
        records = {"CVE-2025-1000": {"inKEV": True, "exploitedKnown": True, "source": ["CISA KEV", "NVD"], "affectedSystems": [{"source": "CISA KEV"}, {"source": "NVD CPE"}]}}
        with patch.object(ingest, "fetch_json", return_value={"count": 1, "vulnerabilities": [{"cveID": "CVE-2025-1001"}]}):
            ingest.kev(records)
        self.assertFalse(records["CVE-2025-1000"]["inKEV"])
        self.assertEqual(records["CVE-2025-1000"]["source"], ["NVD"])
        self.assertEqual(records["CVE-2025-1000"]["affectedSystems"], [{"source": "NVD CPE"}])

    def test_rejected_and_revised(self):
        records = {cid: {"id": cid, "source": ["NVD"], "affectedSystems": [{"source":"NVD CPE","name":"old"}]} for cid in ("CVE-2025-1000","CVE-2025-1001")}
        page = {"totalResults": 2, "vulnerabilities": [{"cve":{"id":"CVE-2025-1000","vulnStatus":"Rejected"}},{"cve":{"id":"CVE-2025-1001"}}]}
        with tempfile.TemporaryDirectory() as tmp, patch.object(ingest,"DATA",Path(tmp)), patch.object(ingest,"fetch",return_value=json.dumps(page).encode()):
            ingest.nvd(records)
        self.assertTrue(records["CVE-2025-1000"]["nvdRejected"])
        self.assertEqual(records["CVE-2025-1001"]["affectedSystems"], [])
