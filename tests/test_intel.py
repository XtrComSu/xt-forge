"""Contract tests for threat intel, the hub client and the cached HTTP layer.

Network is never used: `net.get_json` is mocked, and the cache/offline
behaviour is exercised against a temporary XT_HOME.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import hub, intel, net  # noqa: E402

NVD = {"vulnerabilities": [{"cve": {
    "id": "CVE-2024-3094",
    "descriptions": [{"lang": "en", "value": "Malicious code in xz."}],
    "published": "2024-03-29T00:00:00", "lastModified": "2024-04-01T00:00:00",
    "vulnStatus": "Analyzed",
    "metrics": {"cvssMetricV31": [{"cvssData": {
        "baseScore": 10.0, "baseSeverity": "CRITICAL",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},
    "weaknesses": [{"description": [{"value": "CWE-506"}]}],
    "references": [{"url": "https://example.test/advisory"}],
}}]}


class TestNetCache(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="net-")
        self.env = mock.patch.dict(os.environ, {"XT_HOME": self.tmp})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_offline_without_cache_is_an_honest_error(self):
        with mock.patch.dict(os.environ, {"XT_NET_OFFLINE": "1"}):
            ok, payload, err = net.get_json("https://example.test/x", ttl=60)
        self.assertFalse(ok)
        self.assertIsNone(payload)
        self.assertIn("offline", err)

    def test_writes_and_serves_cache(self):
        body = json.dumps({"v": 1}).encode()
        fake = mock.MagicMock()
        fake.__enter__ = lambda s: s
        fake.__exit__ = lambda *a: False
        fake.read = lambda *a: body
        fake.status = 200
        with mock.patch.dict(os.environ, {"XT_NET_OFFLINE": ""}):
            with mock.patch("urllib.request.urlopen", return_value=fake):
                ok, payload, _ = net.get_json("https://example.test/y", ttl=600)
            self.assertTrue(ok)
            self.assertEqual(payload, {"v": 1})
            # Second call must not touch the network at all.
            with mock.patch("urllib.request.urlopen",
                            side_effect=AssertionError("network used")):
                ok2, payload2, _ = net.get_json("https://example.test/y", ttl=600)
        self.assertTrue(ok2)
        self.assertEqual(payload2, {"v": 1})

    def test_expired_cache_refetches(self):
        path_dir = Path(self.tmp) / "cache" / "net"
        path_dir.mkdir(parents=True, exist_ok=True)
        # ttl=0 means "do not serve stale", which is how expiry is expressed.
        with mock.patch.dict(os.environ, {"XT_NET_OFFLINE": "1"}):
            ok, _, _ = net.get_json("https://example.test/z", ttl=0)
        self.assertFalse(ok)


class TestIntelValidation(unittest.TestCase):
    def test_rejects_non_ip(self):
        self.assertFalse(intel.ip("evil.test/steal")["ok"])

    def test_rejects_private_ip(self):
        res = intel.ip("192.168.1.1")
        self.assertFalse(res["ok"])
        self.assertIn("private", res["err"])

    def test_rejects_malformed_cve(self):
        self.assertFalse(intel.cve("CVE-24-1")["ok"])

    def test_rejects_short_hash(self):
        self.assertFalse(intel.file_hash("abc123")["ok"])

    def test_accepts_valid_digests(self):
        for digest in ("a" * 32, "b" * 40, "c" * 64):
            with mock.patch.object(net, "get_json",
                                   return_value=(True, {"FileName": "x"}, "")):
                self.assertTrue(intel.file_hash(digest)["ok"])


class TestIntelCve(unittest.TestCase):
    def test_composes_three_sources(self):
        with mock.patch.object(net, "get_json") as fetch:
            def route(url, **kw):
                if "nvd.nist.gov" in url:
                    return True, NVD, ""
                if "epss" in url:
                    return True, {"data": [{"epss": "0.91", "percentile": "0.999",
                                            "date": "2026-10-01"}]}, ""
                return True, {"vulnerabilities": []}, ""
            fetch.side_effect = route
            res = intel.cve("CVE-2024-3094")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["cvss"], 10.0)
        self.assertEqual(res["severity"], "CRITICAL")
        self.assertAlmostEqual(res["epss"]["score"], 0.91)
        self.assertIn("CWE-506", res["cwes"])
        self.assertFalse(res["kev"]["listed"])

    def test_kev_listing_becomes_a_risk_flag(self):
        with mock.patch.object(net, "get_json") as fetch:
            fetch.side_effect = lambda url, **kw: (
                (True, NVD, "") if "nvd.nist.gov" in url
                else (True, {"data": []}, "") if "epss" in url
                else (True, {"vulnerabilities": [{
                    "cveID": "CVE-2024-3094", "dateAdded": "2024-04-02",
                    "vendorProject": "Tukaani", "product": "XZ Utils",
                    "vulnerabilityName": "XZ backdoor",
                    "knownRansomwareCampaignUse": "Known"}]}, ""))
            res = intel.cve("CVE-2024-3094")
        self.assertTrue(res["kev"]["listed"])
        self.assertTrue(any("known exploited" in r for r in res["risk"]))
        self.assertTrue(any("ransomware" in r for r in res["risk"]))

    def test_missing_cve_is_an_error(self):
        with mock.patch.object(net, "get_json",
                               return_value=(True, {"vulnerabilities": []}, "")):
            self.assertFalse(intel.cve("CVE-2024-99999")["ok"])


class TestIntelKev(unittest.TestCase):
    CATALOG = {"vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache",
         "product": "Log4j", "vulnerabilityName": "Log4Shell",
         "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2023-4863", "vendorProject": "Google",
         "product": "Chrome", "vulnerabilityName": "WebP",
         "dateAdded": "2023-09-13", "knownRansomwareCampaignUse": "Unknown"},
    ]}

    def test_newest_first(self):
        with mock.patch.object(net, "get_json",
                               return_value=(True, self.CATALOG, "")):
            res = intel.kev()
        self.assertEqual([r["cve"] for r in res["entries"]],
                         ["CVE-2023-4863", "CVE-2021-44228"])

    def test_query_filters(self):
        with mock.patch.object(net, "get_json",
                               return_value=(True, self.CATALOG, "")):
            res = intel.kev("log4j")
        self.assertEqual(res["matched"], 1)
        self.assertEqual(res["entries"][0]["cve"], "CVE-2021-44228")


class TestIntelSearch(unittest.TestCase):
    def test_clamps_the_window_to_120_days(self):
        payload = {"totalResults": 0, "vulnerabilities": []}
        with mock.patch.object(net, "get_json",
                               return_value=(True, payload, "")) as fetch:
            res = intel.search("openssh", since_days=365)
        self.assertTrue(res["clamped"])
        self.assertEqual(res["since_days"], 120)
        self.assertIn("pubStartDate", fetch.call_args[0][0])

    def test_no_keyword_is_an_error(self):
        self.assertFalse(intel.search("   ")["ok"])


class TestIntelIp(unittest.TestCase):
    def test_merges_sources(self):
        def route(url, **kw):
            if "internetdb" in url:
                return True, {"ports": [53, 443], "hostnames": ["dns.google"],
                              "tags": ["dns"], "vulns": [], "cpes": []}, ""
            return True, {"noise": True, "riot": False,
                          "classification": "malicious",
                          "name": "scanner"}, ""
        with mock.patch.object(net, "get_json", side_effect=route):
            res = intel.ip("8.8.8.8")
        self.assertEqual(res["ports"], [53, 443])
        self.assertTrue(res["noise"])
        self.assertIn("observed scanning", " ".join(res["flags"]))

    def test_all_sources_down_is_still_ok_but_degraded(self):
        with mock.patch.object(net, "get_json",
                               return_value=(False, None, "network: down")):
            res = intel.ip("8.8.8.8")
        self.assertTrue(res["ok"])
        self.assertTrue(res["degraded"])
        self.assertTrue(any("no source" in f for f in res["flags"]))


class TestHub(unittest.TestCase):
    def test_models_trim_to_useful_fields(self):
        payload = [{"id": "openbmb/MiniCPM5-2B-GGUF", "downloads": 174828,
                    "likes": 378, "pipeline_tag": "text-generation",
                    "library_name": "gguf", "tags": ["gguf", "chat", "junk"],
                    "lastModified": "2026-10-01T10:00:00", "cardData": {}}]
        with mock.patch.object(net, "get_json", return_value=(True, payload, "")):
            res = hub.models("minicpm", gguf=True)
        self.assertTrue(res["ok"])
        row = res["models"][0]
        self.assertEqual(row["id"], "openbmb/MiniCPM5-2B-GGUF")
        self.assertIn("gguf", row["tags"])
        self.assertNotIn("junk", row["tags"])

    def test_files_reports_quant_menu(self):
        payload = [{"type": "file", "path": "m-q4.gguf", "size": 4 << 30},
                   {"type": "file", "path": "m-q8.gguf", "size": 8 << 30},
                   {"type": "file", "path": "README.md", "size": 2048}]
        with mock.patch.object(net, "get_json", return_value=(True, payload, "")):
            res = hub.files("org/model")
        self.assertTrue(res["ok"])
        self.assertEqual([r["file"] for r in res["gguf"]],
                         ["m-q4.gguf", "m-q8.gguf"])
        self.assertTrue(res["files"][0]["size"].endswith("KB"))

    def test_show_lists_gguf_siblings(self):
        payload = {"pipeline_tag": "text-generation", "downloads": 5,
                   "siblings": [{"rfilename": "a.gguf"},
                                {"rfilename": "b.safetensors"}],
                   "cardData": {"license": "apache-2.0"}}
        with mock.patch.object(net, "get_json", return_value=(True, payload, "")):
            res = hub.show("org/model")
        self.assertEqual(res["gguf_files"], ["a.gguf"])
        self.assertEqual(res["license"], "apache-2.0")

    def test_empty_repo_is_an_error(self):
        self.assertFalse(hub.show("")["ok"])


class TestIntelKeys(unittest.TestCase):
    def test_no_key_means_inactive(self):
        with mock.patch.dict(os.environ, {"XT_VT_KEY": ""}):
            self.assertFalse(intel.key_status()["virustotal"])

    def test_key_activates_the_source(self):
        with mock.patch.dict(os.environ, {"XT_VT_KEY": "secret"}):
            self.assertTrue(intel.key_status()["virustotal"])
            self.assertIn("virustotal", intel.sources()["active"])

    def test_alternate_env_names_are_honoured(self):
        with mock.patch.dict(os.environ,
                             {"VIRUSTOTAL_API_KEY": "secret",
                              "XT_VT_KEY": ""}):
            self.assertTrue(intel.key_status()["virustotal"])

    def test_hash_never_calls_virustotal_without_a_key(self):
        calls = []

        def route(url, **kw):
            calls.append(url)
            return True, {"FileName": "x"}, ""

        with mock.patch.dict(os.environ, {"XT_VT_KEY": ""}):
            with mock.patch.object(net, "get_json", side_effect=route):
                intel.file_hash("a" * 64)
        self.assertFalse(any("virustotal" in url for url in calls))

    def test_hash_attaches_virustotal_when_present(self):
        def route(url, **kw):
            if "virustotal" in url:
                return True, {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": 12, "undetected": 50},
                    "type_description": "ELF", "names": ["evil.elf"]}}}, ""
            return True, {}, "not found"

        with mock.patch.dict(os.environ, {"XT_VT_KEY": "secret"}):
            with mock.patch.object(net, "get_json", side_effect=route):
                res = intel.file_hash("a" * 64)
        self.assertEqual(res["malicious_detections"], 12)
        self.assertEqual(res["sources"]["virustotal"]["malicious"], 12)


class TestCliWiring(unittest.TestCase):
    def test_verbs_registered(self):
        from xtforge.cli import build_parser
        parser = build_parser()
        for argv, attr in ((["intel", "ip", "8.8.8.8"], "intel_verb"),
                           (["intel", "kev"], "intel_verb"),
                           (["intel", "search", "x", "--since", "30"], "since"),
                           (["hub", "models", "qwen", "--gguf"], "gguf"),
                           (["hub", "files", "org/model"], "hub_verb")):
            args = parser.parse_args(argv)
            self.assertTrue(hasattr(args, attr))

    def test_no_new_mcp_schemas(self):
        """Intel and hub are verbs: they cost nothing until called."""
        server = (ROOT / "adapters" / "mcp" / "server.py").read_text()
        for name in ("intel_ip", "intel_cve", "hub_models", "docs_search"):
            self.assertNotIn(f'"{name}"', server)


if __name__ == "__main__":
    unittest.main()
