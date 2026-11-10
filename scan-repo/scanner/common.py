"""Shared by the scanner scripts. Standard library only: these run on a bare GitHub runner."""
import json
import os
from pathlib import Path

# git's well-known empty tree. The scan commit's parent must have this tree, so base...head covers the whole bundle.
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ARTIFACT_PREFIX = "artifact/"
CHECKOUT_PREFIX = "scan-target/"  # where scan.yml checks the bundle out

# The one rule -> severity table (contracts/findings.md). Scripts emit rule ids; only verdict.py decides.
RULES = {
    "GH-000": "error",
    "GH-001": "deny",
    "GH-002": "warn",
    "GH-003": "deny",
    "GH-004": "warn",
    "GH-005": "deny",
    "GH-006": "deny",
    "GH-007": "info",
}


def finding(rule, message, file=None, line=None):
    """One finding in the shape the artifacts platform uses: { rule, severity, file?, line?, message }."""
    out = {"rule": rule, "severity": RULES[rule], "message": message}
    if file:
        out["file"] = strip_prefix(file)
    if line:
        out["line"] = int(line)
    return out


def strip_prefix(path):
    """Bundle-relative path: drops the checkout directory (CodeQL reports scan-target/artifact/...) and artifact/."""
    path = path.removeprefix(CHECKOUT_PREFIX)
    return path[len(ARTIFACT_PREFIX):] if path.startswith(ARTIFACT_PREFIX) else path


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def write_json(path, data):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def set_output(name, value):
    """Writes a step output when running in GitHub Actions; a no-op elsewhere."""
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")
