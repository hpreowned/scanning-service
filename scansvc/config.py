"""All configuration comes from environment variables. Nothing here has a secret default."""
import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Settings:
    scan_repo: str
    default_branch: str
    workflow_file: str
    api_url: str
    server_url: str
    auth_mode: str
    github_token: str | None
    app_id: str | None
    app_installation_id: str | None
    app_private_key: str | None
    scan_store_url: str
    evidence_store_url: str | None
    gitleaks_bin: str | None
    max_bundle_bytes: int
    max_bundle_files: int
    max_file_bytes: int
    scan_timeout_seconds: int
    cache_seconds: int
    max_in_flight: int
    # Callers of the HTTP API (not needed by the in-process CLI or the reconcile job).
    api_auth_mode: str | None
    api_token: str | None
    entra_tenant_id: str | None
    entra_audience: str | None
    entra_allowed_callers: tuple

    def __repr__(self):  # never print credentials, even by accident
        return f"Settings(scan_repo={self.scan_repo!r}, auth_mode={self.auth_mode!r})"


def _private_key(env):
    path = env.get("GITHUB_APP_PRIVATE_KEY_PATH")
    if path:
        return Path(path).read_text(encoding="utf-8")
    return env.get("GITHUB_APP_PRIVATE_KEY")


def load(env=None):
    env = os.environ if env is None else env
    repo = env.get("SCAN_REPO", "")
    if repo.count("/") != 1:
        raise ConfigError("SCAN_REPO must be set to owner/name")
    mode = env.get("GITHUB_AUTH_MODE", "token")
    scan_store = env.get("SCAN_STORE_URL", "./.scan-store")
    evidence_store = env.get("EVIDENCE_STORE_URL") or None
    if scan_store.startswith("https://") and not (evidence_store or "").startswith("https://"):
        raise ConfigError("with a Blob SCAN_STORE_URL, EVIDENCE_STORE_URL must be the https URL of the evidence container")
    settings = Settings(
        scan_repo=repo,
        default_branch=env.get("SCAN_REPO_DEFAULT_BRANCH", "main"),
        workflow_file=env.get("SCAN_WORKFLOW_FILE", "scan.yml"),
        api_url=env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
        server_url=env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/"),
        auth_mode=mode,
        github_token=env.get("GITHUB_TOKEN"),
        app_id=env.get("GITHUB_APP_ID"),
        app_installation_id=env.get("GITHUB_APP_INSTALLATION_ID"),
        app_private_key=_private_key(env) if mode == "app" else None,
        scan_store_url=scan_store,
        evidence_store_url=evidence_store,
        gitleaks_bin=env.get("GITLEAKS_BIN") or None,
        max_bundle_bytes=int(env.get("MAX_BUNDLE_BYTES", 25 * 1024 * 1024)),
        max_bundle_files=int(env.get("MAX_BUNDLE_FILES", 500)),
        max_file_bytes=int(env.get("MAX_FILE_BYTES", 5 * 1024 * 1024)),
        scan_timeout_seconds=int(env.get("SCAN_TIMEOUT_SECONDS", 1200)),
        cache_seconds=int(env.get("SCAN_CACHE_SECONDS", 24 * 3600)),
        max_in_flight=int(env.get("MAX_SCANS_IN_FLIGHT", 20)),
        api_auth_mode=env.get("SCAN_AUTH_MODE") or None,
        api_token=env.get("SCAN_API_TOKEN"),
        entra_tenant_id=env.get("ENTRA_TENANT_ID"),
        entra_audience=env.get("ENTRA_AUDIENCE"),
        entra_allowed_callers=tuple(c.strip() for c in env.get("ENTRA_ALLOWED_CALLERS", "").split(",") if c.strip()),
    )
    if mode == "token" and not settings.github_token:
        raise ConfigError("GITHUB_AUTH_MODE=token needs GITHUB_TOKEN")
    if mode == "app" and not (settings.app_id and settings.app_installation_id and settings.app_private_key):
        raise ConfigError("GITHUB_AUTH_MODE=app needs GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID and a private key")
    if mode not in ("token", "app"):
        raise ConfigError("GITHUB_AUTH_MODE must be token or app")
    return settings
