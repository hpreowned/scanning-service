"""Shared fixtures: settings without credentials, in-memory zips, and fakes that stand in for GitHub and git."""
import io
import json
import zipfile

import pytest

from scansvc import config, metrics
from scansvc.github_api import GitHubError


def make_zip(files, symlinks=()):
    """files: {name: str|bytes}. symlinks: names stored with a symlink mode."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, body in files.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 if name in symlinks else 0o100644) << 16
            archive.writestr(info, body)
    return buffer.getvalue()


def evidence_zip(verdict):
    return make_zip({"verdict.json": json.dumps(verdict), "inventory.json": "{}"})


@pytest.fixture(autouse=True)
def _fresh_metrics():
    metrics.reset()


@pytest.fixture
def settings(tmp_path):
    return config.load({
        "SCAN_REPO": "owner/remote",
        "GITHUB_SERVER_URL": f"file://{tmp_path}",
        "GITHUB_TOKEN": "not-a-real-token",
        "SCAN_STORE_URL": str(tmp_path / "store"),
        "SCAN_TIMEOUT_SECONDS": "600",
    })


class FakeGitHub:
    """GitHub's side of the story, kept across simulated restarts.

    Tests set `run`, `evidence` and `policy` directly. With `auto_run` on, a dispatched request is reported as an
    in-progress run, which is how a real dispatch looks to a process that restarts afterwards.
    """

    def __init__(self):
        self.dispatched, self.deleted, self.cancelled = [], [], []
        self.run, self.evidence, self.policy = None, None, "p1"
        self.fail_next, self.auto_run = None, False

    def _maybe_fail(self):
        if self.fail_next:
            failure, self.fail_next = self.fail_next, None
            raise failure if isinstance(failure, Exception) else GitHubError(failure)

    def dispatch(self, request_id, sha):
        self._maybe_fail()
        self.dispatched.append((request_id, sha))

    def find_run(self, request_id, since=None):
        self._maybe_fail()
        if self.run:
            return self.run
        if self.auto_run and any(rid == request_id for rid, _ in self.dispatched):
            return {"id": 1, "status": "in_progress", "html_url": "https://example.invalid/run/1"}
        return None

    def get_run(self, run_id):
        self._maybe_fail()
        return self.run or {"id": run_id, "status": "in_progress"}

    def download_evidence(self, run_id):
        return self.evidence

    def cancel_run(self, run_id):
        self.cancelled.append(run_id)

    def delete_branch(self, branch):
        self.deleted.append(branch)
        return True

    def policy_version(self):
        return self.policy


class FakeGit:
    """Stands in for scan_repo: no git, no network. The commit SHA depends only on the scan id, as the real one
    depends only on the bytes and the scan id."""

    def __init__(self):
        self.pushed, self.push_error = [], None

    def build_commit(self, workdir, scan_id, paths):
        return (scan_id.replace("-", "") + "c" * 40)[:40]

    def push(self, workdir, settings, token, scan_id, commit_sha):
        if self.push_error:
            raise self.push_error
        self.pushed.append((scan_id, commit_sha))


class Tokens:
    def token(self):
        return "not-a-real-token"


class Clock:
    def __init__(self, start=1_000_000.0):
        self.value = start

    def __call__(self):
        return self.value
