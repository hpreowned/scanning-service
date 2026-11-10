# Scan workspace repo: settings

The repo holds untrusted, AI-generated bundles on `scan/<request-id>` branches and one workflow on the default
branch that judges them. These settings keep a bundle from influencing its own verdict and keep scans fast.

```bash
SCAN_REPO=owner/name ./configure_repo.sh --check    # read-only drift report
SCAN_REPO=owner/name ./configure_repo.sh --apply    # change settings (repo admin)
```

`--check` changes nothing. Run it first and read the report before `--apply`.

## What the script sets

| Area | Setting | Why |
|---|---|---|
| Secret Protection | secret scanning, push protection, generic patterns: on | A push that contains a detectable secret is rejected; the service reports that as GH-005 |
| Code scanning | default setup: not configured | `scan.yml` is the scanner; default setup cannot target `scan/**` |
| Dependency graph | on | Dependency review needs it |
| Actions | only `actions/checkout`, `actions/upload-artifact`, `github/codeql-action/*`; full-SHA pins required | Nothing else can run here |
| Workflow token | read-only; may not approve PRs | The run only reads the repo |
| Retention | 7 days | Evidence is copied to the service's own store |
| Ruleset `scan-protect-default` | PR with code-owner review, no force-push, no deletion | Changing the judge needs security review |
| Ruleset `scan-branches` | only the bypass actor may create, update or delete `scan/**` | Only the scan service writes bundles |
| Ruleset `scan-push-rules` | pushes may not touch `.github/**`; 5 MB file cap; no binaries | Server-side backstop for the `artifact/` nesting rule |

In the real environment set `SCAN_BYPASS_ACTOR_TYPE=Integration` and `SCAN_BYPASS_ACTOR_ID=<GitHub App id>` so the
App is the only writer of `scan/**`. Do not give the App bypass on the default branch.

## What you set by hand

- **Visibility and access.** Private. Write access for the GitHub App only, security team as admins, forking off.
- **Code Security licence** on the repo (private repos). Prefer an org-level security configuration that is
  enforced, so these settings cannot drift.
- **Push protection bypass:** nobody, for this repo.
- **Custom secret patterns** for internal token formats.
- **No repository or environment secrets, ever.** The script reports any it finds.
- **CODEOWNERS:** copy `CODEOWNERS.example` to `.github/CODEOWNERS` with your security team's handle.
- **GitHub App permissions:** Contents read/write, Actions read/write, Metadata read. Installed on this repo only.

## Not available everywhere

- Push rulesets need an organization on a paid plan and a private or internal repo. On other repos the script
  prints `skip` and the check shows `n/a`.
- On a Free plan, CodeQL, secret scanning and dependency review work on public repos only. A public repo is
  acceptable for testing with synthetic bundles and never for real artifacts.

## Housekeeping

Deleted `scan/*` branches leave unreachable objects behind. If the repo grows large, create a fresh one, run
this script against it and point `SCAN_REPO` at it.
