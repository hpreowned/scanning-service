"""Turns CodeQL SARIF into findings. Scanners emit rule ids; the threshold decides GH-001 (deny) or GH-002 (warn)."""
from pathlib import Path

from common import finding, read_json, strip_prefix


def _rules(run):
    """ruleId -> properties, from the driver and every extension (CodeQL puts query metadata in extensions)."""
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + list(tool.get("extensions", []) or [])
    out = {}
    for component in components:
        for rule in component.get("rules", []) or []:
            out[rule.get("id")] = rule.get("properties", {}) or {}
    return out


def _security_severity(properties):
    try:
        return float(properties.get("security-severity"))
    except (TypeError, ValueError):
        return None


def sarif_findings(path, threshold, notebooks=None):
    """Findings from one SARIF file, or None when the file is not a readable SARIF log."""
    data = read_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("runs"), list) or not data["runs"]:
        return None
    notebooks = notebooks or {}
    out = []
    for run in data["runs"]:
        rules = _rules(run)
        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id") or "unknown"
            score = _security_severity(rules.get(rule_id, {}))
            location = ((result.get("locations") or [{}])[0]).get("physicalLocation", {})
            file = strip_prefix((location.get("artifactLocation") or {}).get("uri") or "")
            line = (location.get("region") or {}).get("startLine")
            text = ((result.get("message") or {}).get("text") or "").strip().splitlines()
            message = f"CodeQL {rule_id}" + (f" (security severity {score:g})" if score is not None else "")
            if text:
                message += f": {text[0][:300]}"
            if file in notebooks:
                message += f" [line refers to the code extracted from {notebooks[file]}]"
                file = notebooks[file]
            rule = "GH-001" if score is not None and score >= threshold else "GH-002"
            out.append(finding(rule, message, file or None, line))
    return out


def collect(results_dir, languages, threshold, notebooks=None):
    """Returns (findings, missing_languages). A language CodeQL was asked to analyse must have produced a SARIF file."""
    directory = Path(results_dir) / "codeql"
    files = sorted(directory.glob("*.sarif")) if directory.is_dir() else []
    findings, missing = [], []
    for language in languages:
        stem = language.split("-", 1)[0]  # javascript-typescript -> javascript.sarif
        matches = [f for f in files if f.stem.lower().startswith(stem)]
        parsed = [sarif_findings(f, threshold, notebooks) for f in matches]
        if not matches or any(p is None for p in parsed):
            missing.append(language)
            continue
        for part in parsed:
            findings.extend(part)
    return findings, missing
