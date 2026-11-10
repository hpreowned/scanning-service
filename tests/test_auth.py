"""Entra token validation, with a key pair generated per test run and tokens signed locally. No network."""
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from scansvc.auth import AuthError, EntraAuth, SharedTokenAuth, auth_for
from scansvc import config

TENANT = "11111111-1111-1111-1111-111111111111"
AUDIENCE = "api://scansvc"
WORKER = "22222222-2222-2222-2222-222222222222"      # the scanner worker's client id
STRANGER = "33333333-3333-3333-3333-333333333333"


@pytest.fixture(scope="module")
def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048), \
        rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(key, **overrides):
    now = int(time.time())
    claims = {"iss": f"https://login.microsoftonline.com/{TENANT}/v2.0", "tid": TENANT, "aud": AUDIENCE,
              "azp": WORKER, "oid": "44444444-4444-4444-4444-444444444444", "iat": now, "exp": now + 300}
    claims.update(overrides)
    return "Bearer " + jwt.encode({k: v for k, v in claims.items() if v is not None}, key, algorithm="RS256")


@pytest.fixture
def entra(keys):
    return EntraAuth(TENANT, AUDIENCE, [WORKER], signing_key=lambda _token: keys[0].public_key())


def test_a_token_for_this_service_from_an_allowed_caller_is_accepted(entra, keys):
    assert entra.verify(token(keys[0])) == WORKER
    v1 = token(keys[0], iss=f"https://sts.windows.net/{TENANT}/", azp=None, appid=WORKER)
    assert entra.verify(v1) == WORKER


def test_allowlisting_by_object_id_works_too(keys):
    auth = EntraAuth(TENANT, AUDIENCE, ["44444444-4444-4444-4444-444444444444"],
                     signing_key=lambda _token: keys[0].public_key())
    assert auth.verify(token(keys[0], azp=STRANGER)) == "44444444-4444-4444-4444-444444444444"


@pytest.mark.parametrize("overrides, why", [
    ({"azp": STRANGER, "oid": STRANGER}, "not on the allowlist"),
    ({"aud": "api://something-else"}, "token rejected"),
    ({"exp": int(time.time()) - 10}, "token rejected"),
    ({"tid": "99999999-9999-9999-9999-999999999999"}, "another tenant"),
    ({"iss": "https://login.microsoftonline.com/99999999-9999-9999-9999-999999999999/v2.0"}, "another tenant"),
    ({"exp": None}, "token rejected"),
])
def test_tokens_that_must_be_refused(entra, keys, overrides, why):
    with pytest.raises(AuthError, match=why):
        entra.verify(token(keys[0], **overrides))


def test_a_token_signed_by_someone_else_is_refused(entra, keys):
    with pytest.raises(AuthError, match="token rejected"):
        entra.verify(token(keys[1]))


def test_unsigned_and_malformed_tokens_are_refused(entra, keys):
    unsigned = "Bearer " + jwt.encode({"aud": AUDIENCE, "azp": WORKER}, key="", algorithm="none")
    for header in (unsigned, "Bearer not.a.jwt", "Basic abc", "", None):
        with pytest.raises(AuthError):
            entra.verify(header)


def test_a_failing_key_lookup_never_lets_a_call_through(keys):
    def unreachable(_token):
        raise OSError("JWKS endpoint unreachable")
    auth = EntraAuth(TENANT, AUDIENCE, [WORKER], signing_key=unreachable)
    with pytest.raises(AuthError, match="signing key unavailable"):
        auth.verify(token(keys[0]))


def test_shared_token_mode_and_mode_selection():
    shared = SharedTokenAuth("test-only-value")
    assert shared.verify("Bearer test-only-value") == "shared-token"
    with pytest.raises(AuthError):
        shared.verify("Bearer test-only-valuX")

    base = {"SCAN_REPO": "o/r", "GITHUB_TOKEN": "t"}
    with pytest.raises(ValueError, match="no unauthenticated mode"):
        auth_for(config.load(base))
    with pytest.raises(ValueError, match="ENTRA_ALLOWED_CALLERS"):
        auth_for(config.load({**base, "SCAN_AUTH_MODE": "entra", "ENTRA_TENANT_ID": TENANT, "ENTRA_AUDIENCE": AUDIENCE}))
    with pytest.raises(ValueError, match="SCAN_API_TOKEN"):
        auth_for(config.load({**base, "SCAN_AUTH_MODE": "token"}))
    assert auth_for(config.load({**base, "SCAN_AUTH_MODE": "token", "SCAN_API_TOKEN": "x"})).name == "token"
