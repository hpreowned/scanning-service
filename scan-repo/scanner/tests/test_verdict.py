import tempfile
import unittest
from pathlib import Path

from helpers import sarif

import deps_review
import verdict
from common import write_json

POLICY = {"version": "t", "codeql": {"deny_security_severity": 7.0},
          "dependencies": {"deny_severities": ["critical", "high"]}, "short_circuit": False}
SHA = "a" * 40


def results_dir(inventory=None, deps=None, sarifs=None):
    out = Path(tempfile.mkdtemp(prefix="scan-results-"))
    if inventory is not None:
        write_json(out / "inventory.json", {"ok": True, "codeql_languages": [], "manifests": [], "findings": [],
                                            "notebooks": {}, "unscanned": [], **inventory})
    if deps is not None:
        write_json(out / "deps.json", deps)
    for name, body in (sarifs or {}).items():
        write_json(out / "codeql" / name, body)
    return out


def build(out, policy=POLICY):
    return verdict.build(out, policy, "req-12345678", SHA)


def state(result, name):
    return [s["state"] for s in result["scanners"] if s["name"] == name][0]


class Verdict(unittest.TestCase):
    def test_clean_scan_passes(self):
        out = results_dir({"codeql_languages": ["javascript-typescript"]}, sarifs={"javascript.sarif": sarif([], {})})
        result = build(out)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["commit_sha"], SHA)
        self.assertEqual(state(result, "codeql"), "ran")
        self.assertEqual(state(result, "dependency-review"), "not_applicable")

    def test_high_severity_codeql_result_fails(self):
        body = sarif([("js/xss", "scan-target/artifact/index.html", 12, "DOM text reinterpreted as HTML.\nmore")], {"js/xss": 7.8})
        result = build(results_dir({"codeql_languages": ["javascript-typescript"]}, sarifs={"javascript.sarif": body}))
        self.assertEqual(result["status"], "FAIL")
        found = result["findings"][0]
        self.assertEqual((found["rule"], found["severity"], found["file"], found["line"]), ("GH-001", "deny", "index.html", 12))
        self.assertNotIn("more", found["message"])

    def test_lower_severity_codeql_result_only_warns(self):
        body = sarif([("py/x", "artifact/a.py", 1, "meh")], {"py/x": 5.0})
        result = build(results_dir({"codeql_languages": ["python"]}, sarifs={"python.sarif": body}))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["summary"]["warn"], 1)

    def test_missing_sarif_for_a_requested_language_is_an_error(self):
        result = build(results_dir({"codeql_languages": ["javascript-typescript", "python"]},
                                   sarifs={"javascript.sarif": sarif([], {})}))
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(state(result, "codeql"), "missing")
        self.assertIn("GH-000", [f["rule"] for f in result["findings"]])

    def test_missing_inventory_is_an_error(self):
        self.assertEqual(build(results_dir())["status"], "ERROR")

    def test_failed_tree_check_is_an_error(self):
        out = results_dir()
        write_json(out / "inventory.json", {"ok": False, "error": "outside artifact/"})
        result = build(out)
        self.assertEqual(result["status"], "ERROR")
        self.assertIn("outside artifact/", result["findings"][0]["message"])

    def test_vulnerable_dependency_fails_by_severity(self):
        change = {"manifest": "artifact/package-lock.json", "ecosystem": "npm", "name": "lodash", "version": "4.17.0",
                  "vulnerabilities": [{"severity": "high", "ghsa": "GHSA-x", "summary": "bad", "url": "u"},
                                      {"severity": "moderate", "ghsa": "GHSA-y", "summary": "meh", "url": "u"}]}
        result = build(results_dir({"manifests": ["package-lock.json"]}, deps={"status": "ok", "changes": [change]}))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(sorted(f["rule"] for f in result["findings"]), ["GH-003", "GH-004"])
        self.assertEqual(result["findings"][0]["file"], "package-lock.json")

    def test_dependency_review_error_or_absence_is_an_error(self):
        inv = {"manifests": ["package-lock.json"]}
        self.assertEqual(build(results_dir(inv, deps={"status": "error", "detail": "HTTP 500", "changes": []}))["status"], "ERROR")
        self.assertEqual(build(results_dir(inv))["status"], "ERROR")

    def test_prepare_findings_are_restamped_from_the_rule_table(self):
        inv = {"findings": [{"rule": "GH-006", "severity": "info", "message": "marker", "file": "a.py"}]}
        result = build(results_dir(inv))
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(result["findings"][0]["severity"], "deny")

    def test_notebook_findings_point_at_the_notebook(self):
        body = sarif([("py/cmd", "scan-target/artifact/nb/demo.ipynb.py", 3, "cmd")], {"py/cmd": 9.8})
        inv = {"codeql_languages": ["python"], "notebooks": {"nb/demo.ipynb.py": "nb/demo.ipynb"}}
        found = build(results_dir(inv, sarifs={"python.sarif": body}))["findings"][0]
        self.assertEqual(found["file"], "nb/demo.ipynb")

    def test_short_circuit_skips_codeql_only_when_enabled_and_denied(self):
        inv = {"codeql_languages": ["python"], "findings": [{"rule": "GH-006", "severity": "deny", "message": "m"}]}
        out = results_dir(inv)
        verdict.precheck(out, POLICY)
        self.assertFalse((out / "short_circuit.json").exists())
        verdict.precheck(out, {**POLICY, "short_circuit": True})
        self.assertTrue((out / "short_circuit.json").exists())
        result = build(out)
        self.assertEqual((result["status"], state(result, "codeql")), ("FAIL", "skipped"))


class DependencyReview(unittest.TestCase):
    def call(self, responses, expected):
        calls = iter(responses)
        return deps_review.review("https://api.example.invalid", "o/r", "b", "h", "t", expected,
                                  attempts=3, delay=0, get=lambda url, token: next(calls), sleep=lambda s: None)

    def test_retries_until_the_graph_has_the_bundle(self):
        added = {"change_type": "added", "manifest": "m", "ecosystem": "npm", "name": "a", "version": "1", "vulnerabilities": []}
        result = self.call([(200, {}, []), (200, {}, [added, {**added, "change_type": "removed"}])], expected=1)
        self.assertEqual((result["status"], result["attempts"], len(result["changes"])), ("ok", 2, 1))

    def test_empty_answer_is_fine_when_nothing_is_pinned(self):
        self.assertEqual(self.call([(200, {}, [])], expected=0)["status"], "ok")

    def test_gives_up_closed_when_the_graph_stays_empty(self):
        result = self.call([(200, {}, [])] * 3, expected=4)
        self.assertEqual(result["status"], "error")
        self.assertIn("no entries", result["detail"])

    def test_unavailable_dependency_graph_stops_immediately(self):
        result = self.call([(404, {}, None)], expected=1)
        self.assertEqual((result["status"], result["attempts"]), ("error", 1))


if __name__ == "__main__":
    unittest.main()
