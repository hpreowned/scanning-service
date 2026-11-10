"""Builds the real service from environment settings."""
from . import config
from .github_api import GitHubClient
from .github_auth import provider_for
from .service import ScanService
from .store import store_for


def build_service(settings=None):
    settings = settings or config.load()
    tokens = provider_for(settings)
    return ScanService(settings, store_for(settings), GitHubClient(settings, tokens), tokens)
