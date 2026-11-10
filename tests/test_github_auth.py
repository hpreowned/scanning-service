import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from scansvc import config
from scansvc.github_auth import AppTokenProvider, EnvTokenProvider, provider_for


class Response:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class Http:
    def __init__(self, status=201):
        self.calls, self.status = [], status

    def post(self, url, headers):
        self.calls.append((url, headers))
        return Response(self.status, {"token": f"installation-{len(self.calls)}"})


@pytest.fixture(scope="module")
def keypair():
    # Generated per test run; no key material is stored in the repository.
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pem.decode(), key.public_key()


def test_app_mode_signs_a_short_lived_jwt_and_caches_the_installation_token(keypair):
    pem, public = keypair
    now = [1_700_000_000.0]
    http = Http()
    provider = AppTokenProvider("12345", "678", pem, "https://api.example.invalid", http=http, now=lambda: now[0])
    assert provider.token() == "installation-1"
    url, headers = http.calls[0]
    assert url == "https://api.example.invalid/app/installations/678/access_tokens"
    claims = jwt.decode(headers["Authorization"].removeprefix("Bearer "), public, algorithms=["RS256"],
                        options={"verify_exp": False, "verify_iat": False})
    assert claims["iss"] == "12345" and claims["exp"] - claims["iat"] <= 600

    now[0] += 1800
    assert provider.token() == "installation-1" and len(http.calls) == 1     # still cached
    now[0] += 1800
    assert provider.token() == "installation-2"                               # refreshed near expiry


def test_app_mode_reports_a_refused_token_request(keypair):
    provider = AppTokenProvider("1", "2", keypair[0], "https://api.example.invalid", http=Http(status=401))
    with pytest.raises(RuntimeError, match="HTTP 401"):
        provider.token()


def test_config_picks_the_mode_and_refuses_incomplete_settings(tmp_path, keypair):
    base = {"SCAN_REPO": "o/r"}
    assert isinstance(provider_for(config.load({**base, "GITHUB_TOKEN": "t"})), EnvTokenProvider)
    key_file = tmp_path / "app.pem"
    key_file.write_text(keypair[0])
    app = config.load({**base, "GITHUB_AUTH_MODE": "app", "GITHUB_APP_ID": "1", "GITHUB_APP_INSTALLATION_ID": "2",
                       "GITHUB_APP_PRIVATE_KEY_PATH": str(key_file)})
    assert isinstance(provider_for(app), AppTokenProvider)
    assert "PRIVATE KEY" not in repr(app)
    for broken in ({}, {"SCAN_REPO": "nope"}, {**base}, {**base, "GITHUB_AUTH_MODE": "app", "GITHUB_APP_ID": "1"},
                   {**base, "GITHUB_AUTH_MODE": "other", "GITHUB_TOKEN": "t"}):
        with pytest.raises(config.ConfigError):
            config.load(broken)
