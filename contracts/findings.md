# Findings and rule ids

Every finding is `{ rule, severity, file?, line?, message }`, the same shape the artifacts platform uses, so a
caller can pass them through unchanged. Severities are fixed per rule (`scan-repo/scanner/common.py`); the
thresholds that choose between two rules live in `scan-repo/scanner/policy.json`.

| Rule | Severity | Source | Meaning |
|---|---|---|---|
| GH-000 | error | service, verdict | The scan could not complete: a scanner left no output, the run failed or timed out, or the verdict did not match the commit pushed. Resubmit. |
| GH-001 | deny | CodeQL | Finding with security severity at or above `codeql.deny_security_severity` (default 7.0) |
| GH-002 | warn | CodeQL | Finding below the threshold, or without a security severity |
| GH-003 | deny | dependency review, inventory | Dependency with a known vulnerability at a severity in `dependencies.deny_severities`; or dependencies that are not pinned and so cannot be checked (when `unpinned_manifest` is `deny`) |
| GH-004 | warn | dependency review, inventory | Vulnerable dependency below the threshold; or unpinned dependencies when `unpinned_manifest` is `warn` |
| GH-005 | deny | push protection, gitleaks | A secret was detected. With gitleaks configured, nothing was pushed to GitHub. |
| GH-006 | deny | inventory | Scanner suppression marker or scanner configuration file inside the bundle |
| GH-007 | info | inventory | Files no scanner covers (other languages, non-Python notebook cells, SVG with script) |

## Status

| Status | Meaning | Artifacts platform state |
|---|---|---|
| `running` | Waiting for GitHub | stays `scanning` |
| `PASS` | Every expected scanner ran, nothing is `deny` | continue |
| `FAIL` | At least one `deny` finding | `rejected` |
| `ERROR` | The scan itself did not complete. Blocks exactly like `FAIL`; never auto-allow. | `failed` |

## What the caller must do

- Send the bytes it is going to publish. The verdict is bound to their sha256.
- Publish only when `status` is `PASS` **and** the `sha256` in the answer equals the sha256 of the bytes it holds.
- Never accept a verdict passed along by an agent or a user. Ask this service.
