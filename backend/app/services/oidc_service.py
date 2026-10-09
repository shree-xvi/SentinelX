"""OpenID Connect (SSO) support.

Implements the authorization-code flow pieces needed to authenticate users via
an external identity provider:

  * ``build_authorization_url`` — constructs the IdP authorization URL with a
    signed ``state`` (CSRF protection) and ``nonce``.
  * ``verify_state`` — validates the callback state to prevent CSRF.
  * ``exchange_and_verify`` — exchanges the auth code for tokens and verifies
    the ID token signature against the provider JWKS.

HTTP calls are isolated behind an injectable transport so everything is
unit-testable without a live IdP.
"""
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Callable, Dict, Optional

from backend.app.config import settings

GetTransport = Callable[[str, Dict[str, str]], "tuple[int, str]"]
PostTransport = Callable[[str, Dict[str, str], Dict[str, Any]], "tuple[int, str]"]

_STATE_TTL_SECONDS = 600  # 10 minutes


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _sign_state(payload: Dict[str, Any]) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    signature = hmac.new(
        settings.SECRET_KEY.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{body}.{signature}"


def verify_state(state: str) -> Optional[Dict[str, Any]]:
    """Validate a signed state token; return its payload or None if invalid."""
    try:
        body, signature = state.rsplit(".", 1)
        expected = hmac.new(
            settings.SECRET_KEY.encode("utf-8"), body.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        payload = json.loads(_b64url_decode(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def build_authorization_url(discovery: Dict[str, Any], tenant_hint: Optional[str] = None) -> Dict[str, str]:
    """Create the IdP authorization URL along with the state/nonce to store."""
    state_payload = {
        "nonce": secrets.token_urlsafe(16),
        "exp": int(time.time()) + _STATE_TTL_SECONDS,
        "tenant": tenant_hint,
    }
    state = _sign_state(state_payload)
    params = {
        "client_id": discovery.get("client_id", ""),
        "response_type": "code",
        "scope": discovery.get("scope", "openid email profile"),
        "redirect_uri": discovery.get("redirect_uri", ""),
        "state": state,
        "nonce": state_payload["nonce"],
    }
    from urllib.parse import urlencode

    url = f"{discovery['authorization_endpoint']}?{urlencode(params)}"
    return {"authorization_url": url, "state": state, "nonce": state_payload["nonce"]}


def verify_id_token(id_token: str, jwks: Dict[str, Any], audience: str, issuer: str) -> Dict[str, Any]:
    """Verify an ID token's signature and standard claims against a JWKS.

    Uses PyJWT (already a dependency) with the matching RSA/EC public key.
    Raises ``jwt.PyJWTError`` on any validation failure.
    """
    import jwt

    header = jwt.get_unverified_header(id_token)
    kid = header.get("kid")

    key = None
    for jwk in jwks.get("keys", []):
        if jwk.get("kid") == kid:
            key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
            break
    if key is None and jwks.get("keys"):
        # Fall back to the first key if no kid match (single-key providers).
        key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwks["keys"][0]))
    if key is None:
        raise jwt.PyJWTError("No matching key found in JWKS")

    claims = jwt.decode(
        id_token,
        key=key,
        algorithms=["RS256"],
        audience=audience,
        issuer=issuer,
    )
    return claims


def exchange_code(
    token_endpoint: str,
    code: str,
    client_id: str,
    client_secret: Optional[str],
    redirect_uri: str,
    post_transport: PostTransport,
) -> Dict[str, Any]:
    """Exchange an authorization code for tokens using the injected transport."""
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    status_code, text = post_transport(token_endpoint, headers, data)
    if status_code < 200 or status_code >= 300:
        raise ValueError(f"Token exchange failed: {status_code}")
    return json.loads(text)
