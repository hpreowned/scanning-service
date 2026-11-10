# Deploying the scan service to AKS

Plain manifests with `REPLACE_WITH_...` placeholders. Nothing here contains a credential.

```bash
kubectl apply -k deploy/k8s
```

## Before you apply

1. **Image.** Build with your internal base image and push to your registry:
   `docker build --build-arg BASE_IMAGE=<registry>/python:3.12-slim -t <registry>/scansvc:<tag> .`
2. **Managed identity** with workload identity federation for the `scansvc` service account. It needs
   `Storage Blob Data Contributor` on the `scans` and `scan-evidence` containers and `Key Vault Secrets User`
   on the vault.
3. **Key Vault secret:** `scansvc-github-app-key` (the GitHub App private key, PEM). There is no API token.
4. **Two private containers** in the existing storage account: `scans`, and `scan-evidence` with a time-based
   retention policy. Exclude both from Defender on-upload scanning. See section 8 of `docs/design.md`.
4a. **Entra app registration for the scan service** (its app ID URI is `ENTRA_AUDIENCE`). List the scanner
   worker's client id in `ENTRA_ALLOWED_CALLERS`; the worker requests a token for that audience with its own
   workload identity.
5. **Replace the placeholders** in `serviceaccount.yaml`, `secretproviderclass.yaml`, `configmap.yaml` and the
   two image references.

## Egress the pods need

| Host | Why |
|---|---|
| `api.github.com` (or your GHES / data-residency API host) | dispatch, run status, evidence download |
| `github.com` | git push of the bundle commit |
| The Actions artifact download host your GitHub API redirects to | evidence zip |
| `<vault>.vault.azure.net`, `login.microsoftonline.com` | Key Vault, workload identity |
| `<account>.blob.core.windows.net` | evidence store |

## Notes

- The reconcile job runs every minute and advances scans nobody is polling. It does not serve HTTP.
- `/metrics` and `/healthz` are unauthenticated; the NetworkPolicy limits who can reach the pod.
- Two replicas are safe: state lives in the store and every step is idempotent. Two replicas advancing the same
  scan at once do the same work twice, nothing worse.
- These manifests have not been applied to a cluster yet. Validate with `kubectl apply -k deploy/k8s --dry-run=server`.
