# Scan workspace

This repository scans AI-generated artifact bundles before they are hosted. It is written to by the scan
service only.

- The **default branch** holds the judge: `.github/workflows/scan.yml` and `scanner/`.
- Each submission is one commit on a short-lived `scan/<request-id>` branch. Its parent is an empty baseline
  commit and every file sits under `artifact/`, so nothing in a bundle can act as a workflow or scanner config.
- The scan service dispatches `scan.yml` on the default branch with the request id and the commit SHA. The
  workflow checks the bundle out as data, never installs, builds or runs it, and uploads `scan-evidence`
  (`verdict.json` plus raw scanner output).

## What a scan runs

| Stage | Script | Output |
|---|---|---|
| Tree check, notebook extraction, inventory | `scanner/prepare.py` | `inventory.json` |
| GitHub dependency review, baseline to bundle | `scanner/deps_review.py` | `deps.json` |
| CodeQL (`security-extended`, no build), only for languages present | `github/codeql-action` | `codeql/*.sarif` |
| Verdict | `scanner/verdict.py` | `verdict.json`: `PASS`, `FAIL` or `ERROR` |

`ERROR` means a scanner that should have run left no usable output. It blocks publishing exactly like `FAIL`.

Thresholds live in `scanner/policy.json`. Rule ids and severities are fixed in `scanner/common.py`.

## Tests

```bash
python3 -m unittest discover -s scanner/tests
```

Standard library only; no network.

## Settings

See `setup/README.md`. `setup/configure_repo.sh --check` reports drift without changing anything.
