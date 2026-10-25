import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"scripts"))
import affected
class AffectedTests(unittest.TestCase):
 def test_nvd_ranges(self):
  configs=[{"nodes":[{"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:acme:product:*:*:*:*:*:*:*:*","versionStartIncluding":"1.2","versionEndExcluding":"2.0"},{"vulnerable":False,"criteria":"cpe:2.3:a:other:fixed:1:*:*:*:*:*:*:*"}]}]}]
  rows=affected.nvd_configurations(configs,"CVE-2026-12345")
  self.assertEqual(len(rows),1)
  self.assertEqual(rows[0]["name"],"acme product")
  self.assertEqual(rows[0]["version"],">=1.2, <2.0")
 def test_csaf_known_affected_only(self):
  v={"product_status":{"known_affected":["a"],"fixed":["b"],"known_not_affected":["c"]}}
  rows=affected.csaf_affected(v,{"a":"Controller 2.0","b":"Controller 3.0","c":"Controller 4.0"},"CISA CSAF OT","https://example.org/a")
  self.assertEqual([x["name"] for x in rows],["Controller 2.0"])
 def test_ghsa_package(self):
  row={"vulnerabilities":[{"package":{"ecosystem":"npm","name":"node-lib"},"vulnerable_version_range":"<2.3.4","first_patched_version":{"identifier":"2.3.4"}}]}
  result=affected.ghsa_versions(row)
  self.assertEqual(result[0]["name"],"npm: node-lib")
  self.assertEqual(result[0]["version"],"<2.3.4")
 def test_unknown_not_fabricated(self):
  d=affected.finalize({"id":"CVE-2026-11111","product":"npm","inKEV":False})
  self.assertEqual(d["affectedSystemLabel"],affected.UNKNOWN)
  self.assertEqual(d["affectedSystems"],[])
 def test_kev_product_family(self):
  d=affected.finalize({"id":"CVE-2026-11111","vendor":"Example","product":"Controller","inKEV":True})
  self.assertEqual(d["affectedSystemLabel"],"Example Controller")
if __name__=="__main__":unittest.main()
