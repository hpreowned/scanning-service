"""Fixtures shared by the service tests. Fakes and builders live in fakes.py."""
import pytest

from scansvc import config, metrics


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
