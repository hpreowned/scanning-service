#!/usr/bin/env python3
"""Stage 2 of a scan: GitHub dependency review between the empty baseline and the bundle commit.

Writes results/deps.json. Never raises a verdict itself; `status: error` there becomes ERROR in verdict.py.
The dependency graph can lag a fresh push, so an empty answer for a bundle that has pinned dependencies is retried.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

from common import read_json, write_json

WARNING_HEADER = "x-github-dependency-graph-snapshot-warnings"


def http_get(url, token):
    """Returns (status, headers, parsed_json_or_None). Network errors come back as status 0."""
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "artifact-scan",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as err:
        return err.code, {k.lower(): v for k, v in err.headers.items()}, None
    except (urllib.error.URLError, TimeoutError, ValueError):
        return 0, {}, None


def simplify(changes):
    """Keeps what the verdict needs from the entries the bundle adds."""
    out = []
    for change in changes or []:
        if change.get("change_type") != "added":
            continue
        out.append({
            "manifest": change.get("manifest"),
            "ecosystem": change.get("ecosystem"),
            "name": change.get("name"),
            "version": change.get("version"),
            "vulnerabilities": [{
                "severity": (vuln.get("severity") or "unknown").lower(),
                "ghsa": vuln.get("advisory_ghsa_id"),
                "summary": vuln.get("advisory_summary"),
                "url": vuln.get("advisory_url"),
            } for vuln in change.get("vulnerabilities") or []],
        })
    return out


def review(api, repo, base, head, token, expected, attempts=6, delay=10.0, get=http_get, sleep=time.sleep):
    url = f"{api.rstrip('/')}/repos/{repo}/dependency-graph/compare/{base}...{head}"
    detail = "no attempt made"
    for attempt in range(1, attempts + 1):
        status, headers, body = get(url, token)
        if status == 200 and isinstance(body, list):
            changes = simplify(body)
            if changes or expected == 0:
                return {"status": "ok", "changes": changes, "attempts": attempt,
                        "snapshot_warnings": bool(headers.get(WARNING_HEADER))}
            detail = f"dependency graph returned no entries although the bundle pins {expected} dependencies"
        elif status in (403, 404):
            detail = f"dependency review is not available for this repository (HTTP {status}); enable the dependency graph"
            break
        else:
            detail = f"dependency review request failed (HTTP {status})"
        if attempt < attempts:
            sleep(delay)
    return {"status": "error", "detail": detail, "changes": [], "attempts": attempt}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--results", required=True)
    args = parser.parse_args(argv)
    started = time.time()

    inventory = read_json(os.path.join(args.results, "inventory.json"), {}) or {}
    repo, token = os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GH_TOKEN")
    if not inventory.get("ok") or not repo or not token:
        result = {"status": "error", "detail": "missing inventory, GITHUB_REPOSITORY or GH_TOKEN", "changes": []}
    else:
        result = review(os.environ.get("GITHUB_API_URL", "https://api.github.com"), repo,
                        inventory["base_sha"], inventory["head_sha"], token,
                        int(inventory.get("expected_dependencies", 0)))
    result["elapsed_seconds"] = round(time.time() - started, 1)
    write_json(os.path.join(args.results, "deps.json"), result)
    vulnerable = sum(1 for change in result["changes"] if change["vulnerabilities"])
    print(f"dependency review: {result['status']}, {len(result['changes'])} added, {vulnerable} vulnerable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
