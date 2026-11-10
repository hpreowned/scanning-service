import json
import tempfile
import unittest
from pathlib import Path

from helpers import make_scan_repo

import prepare
from common import read_json

POLICY = str(Path(__file__).resolve().parents[1] / "policy.json")


def run(files, sha=None, **kwargs):
    repo, head = make_scan_repo(files, **kwargs)
    out = Path(tempfile.mkdtemp(prefix="scan-out-"))
    code = prepare.main(["--target", str(repo), "--sha", sha or head, "--policy", POLICY, "--out", str(out)])
    return code, read_json(out / "inventory.json"), repo


def rules(inventory):
    return [f["rule"] for f in inventory["findings"]]


class TreeChecks(unittest.TestCase):
    def test_accepts_a_bundle_nested_under_artifact(self):
        code, inv, _ = run({"artifact/index.html": "<html><script>let a = 1;</script></html>"})
        self.assertEqual(code, 0)
        self.assertTrue(inv["ok"])
        self.assertEqual(inv["codeql_languages"], ["javascript-typescript"])

    def test_rejects_a_file_outside_artifact(self):
        code, inv, _ = run({"artifact/a.js": "1", ".github/workflows/evil.yml": "on: push"})
        self.assertEqual(code, 1)
        self.assertFalse(inv["ok"])
        self.assertIn("outside artifact/", inv["error"])

    def test_workflow_inside_the_bundle_is_inert_and_allowed(self):
        code, inv, _ = run({"artifact/.github/workflows/evil.yml": "on: push", "artifact/a.js": "1"})
        self.assertEqual(code, 0)
        self.assertTrue(inv["ok"])

    def test_rejects_a_commit_without_the_empty_baseline_parent(self):
        code, inv, _ = run({"artifact/a.js": "1"}, baseline=False)
        self.assertEqual(code, 1)
        self.assertIn("no parent", inv["error"])

    def test_rejects_a_sha_mismatch(self):
        code, inv, _ = run({"artifact/a.js": "1"}, sha="0" * 40)
        self.assertEqual(code, 1)
        self.assertIn("is not the requested", inv["error"])

    def test_rejects_executable_files(self):
        code, inv, _ = run({"artifact/run.sh": "echo hi"}, modes={"artifact/run.sh": 0o755})
        self.assertEqual(code, 1)
        self.assertIn("mode 100755", inv["error"])


class Inventory(unittest.TestCase):
    def test_html_without_script_needs_no_codeql(self):
        _, inv, _ = run({"artifact/index.html": "<html><p>hi</p></html>", "artifact/style.css": "p{}"})
        self.assertEqual(inv["codeql_languages"], [])
        self.assertEqual(inv["findings"], [])

    def test_python_and_javascript_are_both_detected(self):
        _, inv, _ = run({"artifact/app.py": "print(1)", "artifact/web/main.ts": "export const a = 1"})
        self.assertEqual(inv["codeql_languages"], ["javascript-typescript", "python"])

    def test_notebook_code_cells_are_extracted_and_other_cells_reported(self):
        notebook = {"metadata": {"kernelspec": {"language": "python"}}, "cells": [
            {"cell_type": "markdown", "source": ["# title"]},
            {"cell_type": "code", "source": ["import os\n", "%pip install x\n", "print(os.getcwd())"]},
            {"cell_type": "code", "source": "%sql\nselect 1"},
        ]}
        _, inv, repo = run({"artifact/nb/demo.ipynb": json.dumps(notebook)})
        self.assertEqual(inv["codeql_languages"], ["python"])
        self.assertEqual(inv["notebooks"], {"nb/demo.ipynb.py": "nb/demo.ipynb"})
        converted = (repo / "artifact/nb/demo.ipynb.py").read_text()
        self.assertIn("import os", converted)
        self.assertIn("# %pip install x", converted)
        self.assertNotIn("select 1", converted)
        self.assertIn("GH-007", rules(inv))

    def test_suppression_file_and_inline_marker_are_findings(self):
        _, inv, _ = run({"artifact/.gitleaksignore": "abc", "artifact/a.py": "x = 1  # nosec\n"})
        self.assertEqual(rules(inv).count("GH-006"), 2)
        marker = [f for f in inv["findings"] if f.get("file") == "a.py"][0]
        self.assertEqual(marker["line"], 1)

    def test_package_json_without_lockfile_is_denied(self):
        _, inv, _ = run({"artifact/package.json": json.dumps({"dependencies": {"left-pad": "1.0.0"}})})
        self.assertIn("GH-003", rules(inv))
        self.assertEqual(inv["manifests"], ["package.json"])

    def test_lockfile_counts_expected_dependencies(self):
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {}, "node_modules/b": {}}}
        _, inv, _ = run({"artifact/package.json": json.dumps({"dependencies": {"a": "1"}}),
                         "artifact/package-lock.json": json.dumps(lock)})
        self.assertNotIn("GH-003", rules(inv))
        self.assertEqual(inv["expected_dependencies"], 2)

    def test_unpinned_requirements_are_reported(self):
        _, inv, _ = run({"artifact/requirements.txt": "flask==3.0.0\nrequests>=2\n# comment\n"})
        self.assertIn("GH-003", rules(inv))
        self.assertEqual(inv["expected_dependencies"], 1)

    def test_uncovered_file_types_are_listed(self):
        _, inv, _ = run({"artifact/a.js": "1", "artifact/query.sql": "select 1", "artifact/vendor.min.js": "x"})
        files = sorted(item["file"] for item in inv["unscanned"])
        self.assertEqual(files, ["query.sql", "vendor.min.js"])
        self.assertIn("GH-007", rules(inv))


if __name__ == "__main__":
    unittest.main()
