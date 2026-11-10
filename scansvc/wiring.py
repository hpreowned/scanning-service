"""Builds the real service from environment settings. The CLI's in-process backend lives here too."""
from . import config
from .github_api import GitHubClient, GitHubError
from .github_auth import provider_for
from .scans import ScanService
from .store import store_for


def build_service(settings=None):
    settings = settings or config.load()
    tokens = provider_for(settings)
    return ScanService(settings, store_for(settings), GitHubClient(settings, tokens), tokens)


class LocalBackend:
    """Same four calls as client.HttpBackend, answered in-process."""

    def __init__(self, service=None):
        self._service = service or build_service()

    def preflight(self):
        try:
            return self._service.github.preflight()
        except GitHubError as err:
            raise RuntimeError(str(err)) from None

    def submit(self, data):
        record, reused = self._service.submit(data)
        return {**record.to_dict(), "reused": reused}

    def status(self, scan_id):
        record = self._service.advance(scan_id)
        return record.to_dict() if record else None

    def reconcile(self):
        return [record.to_dict() for record in self._service.reconcile() if record]
