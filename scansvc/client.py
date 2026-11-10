"""HTTP backend for scanctl: the same calls as wiring.LocalBackend, answered by a running scan service.

SCAN_API_TOKEN is sent as the bearer token. Against a service in entra mode, put an Entra access token for the
service's audience there (for example from `az account get-access-token --resource <audience>`).
"""
import httpx

from .bundle import BundleError, sha256_hex
from .models import Busy


class HttpBackend:
    def __init__(self, base_url, bearer, http=None, job_ref=None):
        if not bearer:
            raise RuntimeError("SCAN_API_TOKEN must be set to call the scan service")
        self._base = base_url.rstrip("/")
        self._http = http or httpx.Client(timeout=120)
        self._headers = {"Authorization": f"Bearer {bearer}"}
        self._job_ref = job_ref

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
        if self._job_ref:
            headers["X-Job-Id"] = self._job_ref
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
