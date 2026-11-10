"""The two ways scanctl can run a scan, with the same four calls and the same answers.

HttpBackend talks to a running scan service. LocalBackend runs the scan in-process.

SCAN_API_TOKEN is sent as the bearer token. Against a service in entra mode, put an Entra access token for the
service's audience there (for example from `az account get-access-token --resource <audience>`).
"""
import httpx

from .bundle import BundleError, sha256_hex
from .models import Busy


class HttpBackend:
    def __init__(self, base_url, bearer, http=None, job_id=None):
        if not bearer:
            raise RuntimeError("SCAN_API_TOKEN must be set to call the scan service")
        self._base = base_url.rstrip("/")
        self._http = http or httpx.Client(timeout=120)
        self._headers = {"Authorization": f"Bearer {bearer}"}
        self._job_id = job_id

    def _fail(self, response):
        try:
            detail = response.json().get("detail", "")
        except ValueError:
            detail = ""
        if response.status_code in (413, 422):
            raise BundleError(detail or f"HTTP {response.status_code}")
        if response.status_code == 429:
            try:
                raise Busy(int(response.headers.get("Retry-After", "30")))
            except ValueError:
                raise Busy() from None
        raise RuntimeError(f"scan service answered HTTP {response.status_code} {detail}".strip())

    def submit(self, data):
        headers = {**self._headers, "Content-Type": "application/zip", "X-Bundle-Sha256": sha256_hex(data)}
        if self._job_id:
            headers["X-Job-Id"] = self._job_id
        response = self._http.post(f"{self._base}/v1/scans", content=data, headers=headers)
        if response.status_code not in (200, 202):
            self._fail(response)
        return response.json()

    def status(self, scan_id):
        response = self._http.get(f"{self._base}/v1/scans/{scan_id}", headers=self._headers)
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            self._fail(response)
        return response.json()

    def preflight(self):
        raise RuntimeError("preflight runs in-process only; unset SCAN_SERVICE_URL")

    def reconcile(self):
        raise RuntimeError("reconcile runs in-process only; unset SCAN_SERVICE_URL")


class LocalBackend:
    def __init__(self, service=None):
        from .wiring import build_service  # imported here so HTTP-only use needs no GitHub settings
        self._service = service or build_service()

    def preflight(self):
        from .github_api import GitHubError
        try:
            return self._service.github.preflight()
        except GitHubError as err:
            raise RuntimeError(str(err)) from None

    def submit(self, data):
        record, reused = self._service.submit(data)
        return record.to_api(reused)

    def status(self, scan_id):
        record = self._service.advance(scan_id)
        return record.to_api() if record else None

    def reconcile(self):
        return [record.to_api() for record in self._service.reconcile() if record]
