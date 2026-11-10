# Artifact scan service

Scans AI-generated artifact bundles with GitHub Code Security before they are hosted. A caller uploads a zip;
the service pushes it to a scan workspace repo, runs one workflow there (CodeQL and dependency review), and
returns `PASS`, `FAIL` or `ERROR`.

```
caller ──zip──▶ scansvc ──commit on scan/<id>──▶ scan workspace repo
                   │   ──workflow_dispatch────▶   scan.yml on the default branch
                   │◀─────────── scan-evidence (verdict.json) ──────────┘
caller ◀─verdict──┘
```

- `scan-repo/` is the content of the scan workspace repo: the workflow, the scanner scripts and the repo
  settings script. See `scan-repo/README.md` and `scan-repo/setup/README.md`.
- `scansvc/` is the service and the `scanctl` CLI.
- `contracts/` is the HTTP contract and the rule ids.

## Rules the design holds to

- The workflow always comes from the scan repo's default branch, never from the scanned commit.
- A bundle is one commit whose parent is an empty baseline and whose files all sit under `artifact/`. Blobs are
  written without git filters, so a `.gitignore` or `.gitattributes` in the bundle cannot hide or rewrite anything.
- Nothing in a bundle is installed, built or executed, by the service or by the workflow.
- `ERROR` blocks. A scanner that left no output, a failed or timed-out run, or a verdict for a different commit
  is never treated as a pass.
- The verdict is bound to the sha256 of the uploaded bytes. Publish only those bytes.
- Every step can run twice. The scan record is saved before each action and written back conditionally, so a
  crash, a retry or a second replica continues the same scan instead of starting another. `tests/test_resume.py`
  kills the process at each step boundary and races replicas to check exactly that.

## Run it on a laptop

```bash
uv venv --python 3.12 .venv && uv pip install -e ".[dev]"
.venv/bin/python -m pytest -q          # offline: no GitHub, no Azure
```

Scan a bundle in-process (needs a scan workspace repo and a token that can push to it and run workflows):

```bash
export SCAN_REPO=owner/name GITHUB_AUTH_MODE=token SCAN_STORE_URL=./.scan-store
export GITHUB_TOKEN="$(gh auth token)"
.venv/bin/scanctl preflight
.venv/bin/scanctl scan tests/fixtures/bundles/static-ok --wait
```

Run the HTTP service and call it:

```bash
export SCAN_AUTH_MODE=token SCAN_API_TOKEN="$(openssl rand -hex 24)"   # laptop only; AKS uses entra
.venv/bin/uvicorn scansvc.app:create_app --factory --port 8080
SCAN_SERVICE_URL=http://localhost:8080 .venv/bin/scanctl scan my-bundle.zip --wait --json
```

`scanctl` exit codes: 0 `PASS`, 1 `FAIL`, 2 `ERROR` or a rejected bundle, 3 still running or at capacity.

Live end-to-end check over the fixture bundles: `python tests/e2e_live.py` (see its docstring).

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `SCAN_REPO` | required | `owner/name` of the scan workspace repo |
| `SCAN_REPO_DEFAULT_BRANCH` | `main` | Branch the workflow is dispatched on |
| `SCAN_WORKFLOW_FILE` | `scan.yml` | Workflow file name |
| `GITHUB_API_URL` | `https://api.github.com` | REST base; override for GHES or data residency |
| `GITHUB_SERVER_URL` | `https://github.com` | Git base for pushes |
| `GITHUB_AUTH_MODE` | `token` | `token` or `app` |
| `GITHUB_TOKEN` | – | Token mode |
| `GITHUB_APP_ID`, `GITHUB_APP_INSTALLATION_ID` | – | App mode |
| `GITHUB_APP_PRIVATE_KEY_PATH` or `GITHUB_APP_PRIVATE_KEY` | – | App mode; a mounted file is preferred |
| `SCAN_AUTH_MODE` | required for the HTTP app | `entra` (AKS) or `token` (laptop). There is no unauthenticated mode. |
| `ENTRA_TENANT_ID`, `ENTRA_AUDIENCE` | – | Entra mode: your tenant, and the audience (app ID URI or client id) tokens must be issued for |
| `ENTRA_ALLOWED_CALLERS` | – | Entra mode: comma-separated client ids or object ids allowed to call the API |
| `SCAN_API_TOKEN` | – | Token mode: the shared bearer. Also what `scanctl` sends as its bearer in HTTP mode |
| `SCAN_SERVICE_URL` | – | Makes `scanctl` call a running service instead of scanning in-process |
| `SCAN_STORE_URL` | `./.scan-store` | Scan records and the sha256 lookup: a directory, or the `https://` URL of the `scans` container |
| `EVIDENCE_STORE_URL` | `<scan store>/evidence` | Evidence, write once: a directory, or the `https://` URL of the `scan-evidence` container (required with a Blob scan store) |
| `MAX_SCANS_IN_FLIGHT` | `20` | Above this, new scans get HTTP 429 with `Retry-After` |
| `GITLEAKS_BIN` | – | Enables the pre-push secret check |
| `MAX_BUNDLE_BYTES` / `MAX_BUNDLE_FILES` / `MAX_FILE_BYTES` | 25 MiB / 500 / 5 MiB | Intake caps |
| `SCAN_TIMEOUT_SECONDS` | `1200` | A scan still running after this becomes `ERROR` |
| `SCAN_CACHE_SECONDS` | `86400` | How long a `PASS`/`FAIL` for the same bytes and policy version is reused |

GitHub App permissions: Contents read/write, Actions read/write, Metadata read, installed on the scan repo only.

## Consumers

- **Artifacts scanner worker:** `POST /v1/scans`, poll `GET /v1/scans/{id}`. Map `FAIL` to `rejected` and
  `ERROR` to `failed`; on `429` wait for `Retry-After`. Send `X-Job-Id` and `traceparent` so the audit trail
  joins up. See `contracts/findings.md` for the caller's obligations.
- **Agents with a shell, CI:** `scanctl` with `SCAN_SERVICE_URL`.
- **Agents over MCP:** expose `contracts/scan-openapi.yaml` through APIM as an MCP server. Bundle bytes go over
  HTTP, not through tool arguments. An agent's scan is a preflight; the publish path asks this service itself.

## Deploy

`GET /metrics` serves Prometheus text; every scan transition is one JSON line on stdout (logger
`scansvc.audit`). The end-to-end design, including storage layout, is in `docs/async-design.md`.

`Dockerfile` builds the service image (`--build-arg BASE_IMAGE=` for an internal base). `deploy/k8s/` holds the
manifests; see `deploy/k8s/README.md`.

## Test status

Verified live on 2026-11-10 against a public test repo on the Free plan, in token mode:

- `tests/e2e_live.py`: all five fixture bundles gave the expected verdict (clean page `PASS`, DOM XSS `FAIL`
  GH-001, vulnerable lodash `FAIL` GH-003, Python command injection `FAIL` GH-001, bundle shipping its own
  workflow `PASS` with no extra workflow or run appearing in the repo).
- A failed CodeQL step produced `ERROR`, a repeated upload was answered from the cache, and every `scan/*`
  branch was deleted afterwards.
- `configure_repo.sh --apply`, including the Actions allowlist and SHA-pin requirement, with scans still passing.
- Push protection (`tests/e2e_live.py --with-secret`): the push was refused, the scan returned `FAIL` GH-005
  with no workflow run, and the commit never reached GitHub.
- One scan takes about four and a half minutes; CodeQL init and analysis are almost all of it.
- Crash and resume: the service was killed right after pushing a bundle, restarted, and given the same bytes
  again. It continued the same scan with the same commit, and GitHub shows exactly one workflow run for it.
- The five fixture bundles were re-run after the resumable-submit rewrite and matched again.

Not tested yet:

- GitHub App mode against GitHub (unit-tested with a generated key and a fake HTTP client).
- Entra token validation against a real tenant (unit-tested with locally signed tokens), and the conditional
  writes against a real storage account (unit-tested against a fake container that enforces ETags).
- gitleaks with a real binary, the Azure Blob store against Azure, and the Kubernetes manifests on a cluster.
- Anything specific to a private repo with Code Security: licensing, push rulesets, org security configuration,
  an enterprise Actions allowlist, runner speed.
