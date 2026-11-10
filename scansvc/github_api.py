"""The few GitHub REST calls the service needs. Tests replace this class with a fake that has the same methods."""
import base64
import json
import time

import httpx


MAX_RUN_PAGES = 10


class GitHubError(Exception):
    def __init__(self, message, status=0):
        super().__init__(message)
        self.status = status

    @property
    def permanent(self):
        """True when retrying cannot help (bad request, missing workflow, no permission)."""
        return 400 <= self.status < 500 and self.status not in (408, 429)


class GitHubClient:
    def __init__(self, settings, tokens, http=None):
        self._settings, self._tokens = settings, tokens
        self._http = http or httpx.Client(timeout=30, follow_redirects=True)
        self._base = f"{settings.api_url}/repos/{settings.scan_repo}"

    def _request(self, method, url, **kwargs):
        headers = {
            "Authorization": f"Bearer {self._tokens.token()}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "scansvc",
        }
        try:
            return self._http.request(method, url, headers=headers, **kwargs)
        except httpx.HTTPError as err:
            raise GitHubError(f"GitHub request failed: {type(err).__name__}") from None

    def _json(self, method, path, expected=(200,), **kwargs):
        response = self._request(method, self._base + path, **kwargs)
        if response.status_code not in expected:
            raise GitHubError(f"GitHub answered HTTP {response.status_code} to {method} {path.split('?')[0]}",
                              status=response.status_code)
        return response.json() if response.content else None

    def preflight(self):
        """Raises GitHubError with a clear message when the service cannot do its job with these credentials."""
        repo = self._json("GET", "")
        permissions = repo.get("permissions") or {}
        if permissions and not permissions.get("push"):
            raise GitHubError(f"the credentials cannot push to {self._settings.scan_repo}")
        workflow = f"/contents/.github/workflows/{self._settings.workflow_file}?ref={self._settings.default_branch}"
        if self._request("GET", self._base + workflow).status_code != 200:
            raise GitHubError(f"{self._settings.workflow_file} is not on {self._settings.default_branch}")
        return {"visibility": repo.get("visibility"), "default_branch": repo.get("default_branch")}

    def policy_version(self):
        path = f"/contents/scanner/policy.json?ref={self._settings.default_branch}"
        body = self._json("GET", path)
        return json.loads(base64.b64decode(body["content"])).get("version", "unknown")

    def dispatch(self, request_id, sha):
        path = f"/actions/workflows/{self._settings.workflow_file}/dispatches"
        payload = {"ref": self._settings.default_branch, "inputs": {"request_id": request_id, "sha": sha}}
        self._json("POST", path, expected=(200, 204), json=payload)

    def find_run(self, request_id, since=None):
        """The dispatched run for this request, or None if GitHub has not created it yet.

        Only a run of our workflow file, dispatched on the default branch, is accepted: a run started any other
        way is not the judge. `since` (epoch seconds, the scan's creation time) bounds the search, and the search
        pages through results, so it does not depend on the run being among the newest few.
        """
        path = f"/actions/workflows/{self._settings.workflow_file}/runs"
        params = {"event": "workflow_dispatch", "per_page": 100}
        if since:
            stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since - 120))  # tolerate clock skew
            params["created"] = f">={stamp}"
        for page in range(1, MAX_RUN_PAGES + 1):
            runs = self._json("GET", path, params={**params, "page": page}).get("workflow_runs", [])
            for run in runs:
                if (run.get("display_title") == f"scan {request_id}"
                        and run.get("head_branch") == self._settings.default_branch
                        and run.get("event") == "workflow_dispatch"
                        and str(run.get("path", "")).endswith(f"/{self._settings.workflow_file}")):
                    return run
            if len(runs) < params["per_page"]:
                break
        return None

    def get_run(self, run_id):
        return self._json("GET", f"/actions/runs/{run_id}")

    def cancel_run(self, run_id):
        self._request("POST", f"{self._base}/actions/runs/{run_id}/cancel")

    def download_evidence(self, run_id, name="scan-evidence"):
        """The evidence artifact zip as bytes, or None when the run did not upload one."""
        artifacts = self._json("GET", f"/actions/runs/{run_id}/artifacts").get("artifacts", [])
        match = [a for a in artifacts if a.get("name") == name and not a.get("expired")]
        if not match:
            return None
        response = self._request("GET", f"{self._base}/actions/artifacts/{match[0]['id']}/zip")
        if response.status_code != 200:
            raise GitHubError(f"evidence download failed (HTTP {response.status_code})")
        return response.content

    def delete_branch(self, branch):
        response = self._request("DELETE", f"{self._base}/git/refs/heads/{branch}")
        return response.status_code in (204, 404, 422)
