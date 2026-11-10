#!/usr/bin/env python3
"""Last stage of a scan: combine every scanner's output into verdict.json.

PASS  every expected scanner ran and nothing is `deny`.
FAIL  at least one `deny` finding.
ERROR a scanner that should have run left no usable output. ERROR blocks, exactly like FAIL.
"""
import argparse
import sys
import time
from pathlib import Path

from common import RULES, finding, read_json, set_output, write_json
from sarif import collect

SCHEMA = 1


def dependency_findings(deps, policy):
    deny = {s.lower() for s in (policy.get("dependencies") or {}).get("deny_severities", ["critical", "high"])}
    out = []
    for change in deps.get("changes", []):
        for vuln in change.get("vulnerabilities", []):
            rule = "GH-003" if vuln.get("severity") in deny else "GH-004"
            out.append(finding(rule, f"{change.get('name')}@{change.get('version')} ({change.get('ecosystem')}): "
                               f"{vuln.get('ghsa')} {vuln.get('severity')} - {vuln.get('summary')}", change.get("manifest")))
    return out


def early_findings(results, policy):
    """Findings available before CodeQL runs, plus the state of the two scanners that produced them."""
    inventory = read_json(Path(results) / "inventory.json")
    scanners, findings = [], []
    if not inventory:
        scanners.append({"name": "prepare", "state": "missing", "detail": "inventory.json was not produced"})
        return None, scanners, findings
    if not inventory.get("ok"):
        scanners.append({"name": "prepare", "state": "failed", "detail": inventory.get("error", "tree check failed")})
        return inventory, scanners, findings
    scanners.append({"name": "prepare", "state": "ran"})
    findings.extend(inventory.get("findings", []))

    if not inventory.get("manifests"):
        scanners.append({"name": "dependency-review", "state": "not_applicable"})
    else:
        deps = read_json(Path(results) / "deps.json")
        if not deps:
            scanners.append({"name": "dependency-review", "state": "missing", "detail": "deps.json was not produced"})
        elif deps.get("status") != "ok":
            scanners.append({"name": "dependency-review", "state": "failed", "detail": deps.get("detail", "")})
        else:
            scanners.append({"name": "dependency-review", "state": "ran", "seconds": deps.get("elapsed_seconds")})
            findings.extend(dependency_findings(deps, policy))
    return inventory, scanners, findings


def build(results, policy, request_id, sha):
    inventory, scanners, findings = early_findings(results, policy)
    languages = (inventory or {}).get("codeql_languages", []) if (inventory or {}).get("ok") else []
    short_circuited = (Path(results) / "short_circuit.json").exists()
    if inventory and inventory.get("ok"):
        if not languages:
            scanners.append({"name": "codeql", "state": "not_applicable"})
        elif short_circuited:
            scanners.append({"name": "codeql", "state": "skipped", "detail": "policy short_circuit: an earlier stage already denied"})
        else:
            threshold = float((policy.get("codeql") or {}).get("deny_security_severity", 7.0))
            found, missing = collect(results, languages, threshold, inventory.get("notebooks"))
            findings.extend(found)
            if missing:
                scanners.append({"name": "codeql", "state": "missing", "languages": languages,
                                 "detail": "no SARIF output for: " + ", ".join(missing)})
            else:
                scanners.append({"name": "codeql", "state": "ran", "languages": languages})

    broken = [s for s in scanners if s["state"] in ("missing", "failed")]
    for scanner in broken:
        findings.append(finding("GH-000", f"{scanner['name']} did not complete: {scanner.get('detail', scanner['state'])}"))
    # Stamp severities from the table, whatever a scanner wrote.
    findings = [{**f, "severity": RULES[f["rule"]]} for f in findings]
    counts = {level: sum(1 for f in findings if f["severity"] == level) for level in ("deny", "warn", "info", "error")}
    status = "ERROR" if broken else ("FAIL" if counts["deny"] else "PASS")
    return {
        "schema": SCHEMA,
        "request_id": request_id,
        "commit_sha": sha,
        "status": status,
        "policy_version": policy.get("version", "unknown"),
        "summary": counts,
        "findings": findings,
        "scanners": scanners,
        "unscanned": (inventory or {}).get("unscanned", []),
        "generated_at": int(time.time()),
    }


def precheck(results, policy):
    """With policy.short_circuit on, skips CodeQL when an earlier stage has already produced a deny."""
    blocked = False
    if policy.get("short_circuit"):
        _, _, findings = early_findings(results, policy)
        blocked = any(RULES[f["rule"]] == "deny" for f in findings)
        if blocked:
            write_json(Path(results) / "short_circuit.json", {"blocked": True})
    set_output("blocked", "true" if blocked else "false")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--precheck", action="store_true")
    parser.add_argument("--request-id", default="")
    parser.add_argument("--sha", default="")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    policy = read_json(args.policy, {}) or {}
    if args.precheck:
        return precheck(args.results, policy)
    verdict = build(args.results, policy, args.request_id, args.sha)
    write_json(args.out or Path(args.results) / "verdict.json", verdict)
    print(f"verdict: {verdict['status']} {verdict['summary']}")
    # Exit 0 on FAIL too: the run succeeding means "the scan completed", the verdict file carries the answer.
    return 0


if __name__ == "__main__":
    sys.exit(main())
