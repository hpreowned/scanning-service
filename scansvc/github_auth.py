"""Two ways to get a GitHub token, behind one interface.

token mode: a token from the environment (laptop tests).
app mode:   a GitHub App installation token, minted from the App's private key and cached until near expiry.
"""
import time
from typing import Protocol

import httpx
import jwt


class TokenProvider(Protocol):
    def token(self) -> str: ...


class EnvTokenProvider:
    def __init__(self, token):
        self._token = token

    def token(self):
        return self._token


class AppTokenProvider:
    def __init__(self, app_id, installation_id, private_key, api_url, http=None, now=time.time):
        self._app_id, self._installation_id, self._key = app_id, installation_id, private_key
        self._api_url, self._http, self._now = api_url, http or httpx.Client(timeout=30), now
        self._cached, self._expires = None, 0.0

    def _app_jwt(self):
        issued = int(self._now())
        # 60 s in the past for clock drift, 9 min lifetime (GitHub allows at most 10).
        return jwt.encode({"iat": issued - 60, "exp": issued + 540, "iss": str(self._app_id)}, self._key, algorithm="RS256")

    def token(self):
        if self._cached and self._now() < self._expires - 120:
            return self._cached
        response = self._http.post(
            f"{self._api_url}/app/installations/{self._installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {self._app_jwt()}", "Accept": "application/vnd.github+json"},
        )
        if response.status_code != 201:
            raise RuntimeError(f"could not mint a GitHub App installation token (HTTP {response.status_code})")
        body = response.json()
        self._cached = body["token"]
        # Installation tokens last one hour; refresh on our own clock rather than parsing the timestamp.
        self._expires = self._now() + 3600
        return self._cached


def provider_for(settings):
    if settings.auth_mode == "app":
        return AppTokenProvider(settings.app_id, settings.app_installation_id, settings.app_private_key, settings.api_url)
    return EnvTokenProvider(settings.github_token)
