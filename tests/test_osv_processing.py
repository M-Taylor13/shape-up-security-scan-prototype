# Unit tests for turning OSV-Scanner output into dashboard findings
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))

import process_results  # noqa: E402


def vulnerability(vuln_id, package, fixed, summary=None, rating=None, range_type="SEMVER"):
    vuln = {
        "id": vuln_id,
        "affected": [{
            "package": {"name": package},
            "ranges": [{"type": range_type, "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
    }
    if summary:
        vuln["summary"] = summary
    if rating:
        vuln["database_specific"] = {"severity": rating}
    return vuln


def report(*packages, path="app/package-lock.json"):
    return {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": list(packages)}]}


def package(name, version, ecosystem, vulnerabilities, groups=None):
    entry = {
        "package": {"name": name, "version": version, "ecosystem": ecosystem},
        "vulnerabilities": vulnerabilities,
    }
    if groups is not None:
        entry["groups"] = groups
    return entry


class OsvProcessingTests(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.original = (process_results.RESULTS, process_results.ROOT)
        process_results.ROOT = Path(self.directory.name).resolve()
        process_results.RESULTS = process_results.ROOT / "results"
        process_results.RESULTS.mkdir()
        self.addCleanup(self.restore)

    def restore(self):
        process_results.RESULTS, process_results.ROOT = self.original

    def findings(self, data):
        (process_results.RESULTS / "osv-scanner.json").write_text(json.dumps(data))
        return process_results.process_osv_scanner()

    def test_missing_or_empty_results_give_no_findings(self):
        self.assertEqual([], process_results.process_osv_scanner())
        self.assertEqual([], self.findings({"results": []}))
        self.assertEqual([], self.findings({"results": None}))
        (process_results.RESULTS / "osv-scanner.json").write_text("not json")
        self.assertEqual([], process_results.process_osv_scanner())

    def test_finding_uses_the_common_format(self):
        vuln = vulnerability("GHSA-aaaa", "minimist", "1.2.6", summary="Prototype Pollution in minimist")
        groups = [{"ids": ["GHSA-aaaa"], "aliases": ["CVE-2021-44906", "GHSA-aaaa"], "max_severity": "9.8"}]
        path = str(process_results.ROOT / "app" / "package-lock.json")
        finding, = self.findings(report(package("minimist", "1.2.0", "npm", [vuln], groups), path=path))

        self.assertEqual("OSV-Scanner", finding["scanner"])
        self.assertEqual("SCA", finding["type"])
        self.assertEqual("GHSA-aaaa", finding["category"])
        self.assertEqual("minimist 1.2.0: Prototype Pollution in minimist", finding["title"])
        self.assertEqual("CRITICAL", finding["severity"])
        self.assertEqual("FAIL", finding["status"])
        self.assertEqual("app/package-lock.json", finding["file"])
        self.assertIsNone(finding["line"])
        self.assertEqual(("minimist", "1.2.0", "npm"), (finding["package"], finding["version"], finding["ecosystem"]))
        self.assertEqual("1.2.6", finding["fixed_version"])
        self.assertEqual(["CVE-2021-44906", "GHSA-aaaa"], finding["aliases"])
        self.assertIn("minimist 1.2.0 (npm): Prototype Pollution in minimist.", finding["message"])
        self.assertIn("Fix by upgrading minimist from 1.2.0 to 1.2.6 or later.", finding["message"])

    def test_every_ecosystem_is_reported(self):
        data = {"results": [
            {"source": {"path": "web/package-lock.json"}, "packages": [
                package("lodash", "4.17.15", "npm", [vulnerability("GHSA-1", "lodash", "4.17.21")])]},
            {"source": {"path": "api/requirements.txt"}, "packages": [
                package("urllib3", "1.26.4", "PyPI", [vulnerability("PYSEC-1", "urllib3", "1.26.5")])]},
            {"source": {"path": "svc/go.mod"}, "packages": [
                package("golang.org/x/text", "0.3.5", "Go", [vulnerability("GO-1", "golang.org/x/text", "0.3.7")])]},
            {"source": {"path": "java/pom.xml"}, "packages": [
                package("log4j-core", "2.14.1", "Maven", [vulnerability("GHSA-2", "log4j-core", "2.15.0")])]},
        ]}
        findings = self.findings(data)
        self.assertEqual(["npm", "PyPI", "Go", "Maven"], [finding["ecosystem"] for finding in findings])
        self.assertEqual(
            ["web/package-lock.json", "api/requirements.txt", "svc/go.mod", "java/pom.xml"],
            [finding["file"] for finding in findings])

    def test_aliases_of_one_vulnerability_become_one_finding(self):
        vulns = [
            vulnerability("PYSEC-2023-192", "urllib3", "1.26.17"),
            vulnerability("GHSA-v845", "urllib3", "1.26.17", summary="Cookie header not stripped on redirect"),
        ]
        groups = [{"ids": ["PYSEC-2023-192", "GHSA-v845"],
                   "aliases": ["CVE-2023-43804", "GHSA-v845", "PYSEC-2023-192"], "max_severity": "8.1"}]
        finding, = self.findings(report(package("urllib3", "1.26.4", "PyPI", vulns, groups)))
        self.assertEqual("PYSEC-2023-192", finding["category"])
        self.assertEqual("HIGH", finding["severity"])
        self.assertIn("Cookie header not stripped on redirect", finding["message"])

    def test_title_names_package_and_vulnerability(self):
        title = process_results.osv_title
        self.assertEqual("lodash 4.17.15: Command Injection in lodash",
                         title("lodash", "4.17.15", [{"summary": "Command Injection in lodash."}], "GHSA-1"))
        # The summary may sit on any alias of the vulnerability.
        self.assertEqual("urllib3 1.26.4: Cookie leak",
                         title("urllib3", "1.26.4", [{"details": "Long text."}, {"summary": "Cookie  leak"}], "PYSEC-1"))
        # No summary anywhere: fall back to the ID rather than the long details.
        self.assertEqual("urllib3 1.26.4: PYSEC-2021-108",
                         title("urllib3", "1.26.4", [{"details": "Long text."}], "PYSEC-2021-108"))
        long_title = title("pkg", "1.0.0", [{"summary": "x" * 200}], "V")
        self.assertTrue(long_title.endswith("..."))
        self.assertEqual(len("pkg 1.0.0: ") + 80, len(long_title))

    def test_package_without_groups_reports_each_vulnerability(self):
        vulns = [vulnerability("GHSA-1", "lodash", "4.17.21"), vulnerability("GHSA-2", "lodash", "4.17.19")]
        findings = self.findings(report(package("lodash", "4.17.15", "npm", vulns)))
        self.assertEqual(["GHSA-1", "GHSA-2"], [finding["category"] for finding in findings])

    def test_severity_follows_cvss_score(self):
        cases = {"9.8": "CRITICAL", "9.0": "CRITICAL", "8.9": "HIGH", "7.0": "HIGH",
                 "6.9": "MEDIUM", "4.0": "MEDIUM", "3.9": "LOW", "0.1": "LOW"}
        for score, expected in cases.items():
            self.assertEqual(expected, process_results.osv_severity(score, []), score)

    def test_severity_falls_back_to_advisory_rating_then_high(self):
        self.assertEqual("MEDIUM", process_results.osv_severity("", [{"database_specific": {"severity": "MODERATE"}}]))
        self.assertEqual("LOW", process_results.osv_severity(None, [{"database_specific": {"severity": "low"}}]))
        self.assertEqual("HIGH", process_results.osv_severity("", [{}]))
        self.assertEqual("HIGH", process_results.osv_severity("not-a-number", []))
        self.assertEqual("HIGH", process_results.osv_severity("0", []))

    def test_status_follows_project_criteria(self):
        statuses = {}
        for score in ("9.8", "7.5", "5.0", "2.0"):
            groups = [{"ids": ["V"], "max_severity": score}]
            finding, = self.findings(report(package("pkg", "1.0.0", "npm", [vulnerability("V", "pkg", "2.0.0")], groups)))
            statuses[finding["severity"]] = finding["status"]
        self.assertEqual({"CRITICAL": "FAIL", "HIGH": "FAIL", "MEDIUM": "WARN", "LOW": "PASS"}, statuses)

    def test_fixed_version_is_lowest_one_above_installed(self):
        vuln = {"id": "V", "affected": [{"package": {"name": "minimist"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.2.1"}]},
            {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.3"}]},
        ]}]}
        self.assertEqual("1.2.3", process_results.osv_fixed_version("minimist", "1.2.0", [vuln]))
        self.assertEqual("0.2.1", process_results.osv_fixed_version("minimist", "0.0.8", [vuln]))
        self.assertEqual("1.10.0", process_results.osv_fixed_version("pkg", "1.9.0", [
            vulnerability("A", "pkg", "1.10.0"), vulnerability("B", "pkg", "1.2.0")]))

    def test_fixed_version_ignores_commit_hashes_and_other_packages(self):
        vulns = [
            vulnerability("A", "urllib3", "2d4a3fee6de2fa45", range_type="GIT"),
            vulnerability("B", "another-package", "9.9.9"),
            vulnerability("C", "URLLIB3", "1.26.5", range_type="ECOSYSTEM"),
        ]
        self.assertEqual("1.26.5", process_results.osv_fixed_version("urllib3", "1.26.4", vulns))

    def test_missing_fix_is_stated(self):
        vuln = {"id": "V", "affected": [{"package": {"name": "pkg"}, "ranges": [
            {"type": "SEMVER", "events": [{"introduced": "0"}]}]}]}
        finding, = self.findings(report(package("pkg", "1.0.0", "npm", [vuln])))
        self.assertIsNone(finding["fixed_version"])
        self.assertIn("No fixed version is published yet.", finding["message"])

    def test_non_numeric_versions_still_get_a_suggestion(self):
        self.assertEqual("1.0.0-beta.2", process_results.osv_fixed_version(
            "pkg", "1.0.0-beta.1", [vulnerability("V", "pkg", "1.0.0-beta.2")]))

    def test_scannerignore_matches_id_alias_or_file(self):
        (process_results.ROOT / ".scannerignore").write_text("# comment\nCVE-2023-43804\nlegacy/\n")
        findings = [
            {"category": "PYSEC-2023-192", "file": "requirements.txt", "aliases": ["CVE-2023-43804"]},
            {"category": "GHSA-keep", "file": "requirements.txt", "aliases": ["CVE-2020-0001"]},
            {"category": "GHSA-other", "file": "legacy/package-lock.json", "aliases": []},
            {"category": "python.sql-injection", "file": "app.py"},
        ]
        kept = process_results.filter_ignored_findings(findings)
        self.assertEqual(["GHSA-keep", "python.sql-injection"], [finding["category"] for finding in kept])


if __name__ == "__main__":
    unittest.main()
