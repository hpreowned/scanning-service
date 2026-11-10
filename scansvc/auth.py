"""Who may call the HTTP API.

entra: the caller presents a Microsoft Entra access token issued for this service (workload identity in AKS,
       or any app registration). Signature, issuer, tenant, audience and expiry are checked, and the calling
       application or identity must be on an allowlist. No shared secret exists anywhere.
token: one shared bearer token from the environment. For a laptop only.

Both return a short caller name that is recorded on the scan.
"""
import hmac

import jwt


class AuthError(Exception):
    pass


def _bearer(header):
    if not header or not header.lower().startswith("bearer "):
        raise AuthError("missing bearer token")
    return header[7:].strip()


class SharedTokenAuth:
    name = "token"

    def __init__(self, token):
        if not token:
            raise ValueError("SCAN_AUTH_MODE=token needs SCAN_API_TOKEN")
        self._token = token

    def verify(self, header):
        if not hmac.compare_digest(_bearer(header).encode(), self._token.encode()):
            raise AuthError("wrong bearer token")
        return "shared-token"


class EntraAuth:
    name = "entra"

    def __init__(self, tenant_id, audience, allowed_callers, signing_key=None):
        if not (tenant_id and audience and allowed_callers):
            raise ValueError("SCAN_AUTH_MODE=entra needs ENTRA_TENANT_ID, ENTRA_AUDIENCE and ENTRA_ALLOWED_CALLERS")
        self._tenant, self._audience, self._allowed = tenant_id, audience, set(allowed_callers)
        self._issuers = {f"https://login.microsoftonline.com/{tenant_id}/v2.0", f"https://sts.windows.net/{tenant_id}/"}
        if signing_key is None:
            jwks = jwt.PyJWKClient(f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys", cache_keys=True)
            signing_key = lambda token: jwks.get_signing_key_from_jwt(token).key  # noqa: E731
        self._signing_key = signing_key

    def verify(self, header):
        token = _bearer(header)
        try:
            claims = jwt.decode(token, self._signing_key(token), algorithms=["RS256"], audience=self._audience,
                                options={"require": ["exp", "iat", "aud", "iss"]})
        except jwt.PyJWTError as err:
            raise AuthError(f"token rejected: {type(err).__name__}") from None
        except Exception as err:  # key lookup failures (unknown kid, JWKS unreachable) must never let a call through
            raise AuthError(f"signing key unavailable: {type(err).__name__}") from None
        if claims.get("iss") not in self._issuers or claims.get("tid") != self._tenant:
            raise AuthError("token is from another tenant or issuer")
        # App-only tokens carry the client id in azp (v2) or appid (v1), and the service principal in oid.
        identities = {claims.get("azp"), claims.get("appid"), claims.get("oid")} - {None}
        allowed = identities & self._allowed
        if not allowed:
            raise AuthError("caller is not on the allowlist")
        return sorted(allowed)[0]


def auth_for(settings):
    mode = settings.api_auth_mode
    if mode == "entra":
        return EntraAuth(settings.entra_tenant_id, settings.entra_audience, settings.entra_allowed_callers)
    if mode == "token":
        return SharedTokenAuth(settings.api_token)
    raise ValueError("SCAN_AUTH_MODE must be set to entra or token; the API has no unauthenticated mode")
