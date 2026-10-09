import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.app.services import oidc_service


def _generate_rsa_jwks():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kid = "test-key-1"
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
    public_jwk["kid"] = kid
    public_jwk["alg"] = "RS256"
    public_jwk["use"] = "sig"
    return private_pem, {"keys": [public_jwk]}, kid


_DISCOVERY = {
    "authorization_endpoint": "https://idp.example.com/authorize",
    "client_id": "client-123",
    "scope": "openid email",
    "redirect_uri": "https://app.example.com/callback",
}


def test_state_roundtrip_valid():
    result = oidc_service.build_authorization_url(_DISCOVERY, tenant_hint="acme")
    assert result["authorization_url"].startswith("https://idp.example.com/authorize?")
    assert "state=" in result["authorization_url"]
    assert result["nonce"]

    payload = oidc_service.verify_state(result["state"])
    assert payload is not None
    assert payload["tenant"] == "acme"
    assert payload["nonce"] == result["nonce"]


def test_verify_state_rejects_tampered():
    state = oidc_service.build_authorization_url(_DISCOVERY)["state"]
    tampered = state[:-2] + ("aa" if not state.endswith("aa") else "bb")
    assert oidc_service.verify_state(tampered) is None


def test_verify_state_rejects_expired():
    original = oidc_service._sign_state
    try:
        oidc_service._sign_state = lambda payload: original({**payload, "exp": int(time.time()) - 100})
        state = oidc_service.build_authorization_url(_DISCOVERY)["state"]
        assert oidc_service.verify_state(state) is None
    finally:
        oidc_service._sign_state = original


def test_verify_id_token_valid():
    private_pem, jwks, kid = _generate_rsa_jwks()
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": "https://idp.example.com",
            "aud": "client-123",
            "sub": "user-42",
            "email": "jane@acme.com",
            "name": "Jane Doe",
            "iat": now,
            "exp": now + 3600,
        },
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    claims = oidc_service.verify_id_token(
        token, jwks, audience="client-123", issuer="https://idp.example.com"
    )
    assert claims["email"] == "jane@acme.com"
    assert claims["sub"] == "user-42"


def test_verify_id_token_rejects_wrong_audience():
    private_pem, jwks, kid = _generate_rsa_jwks()
    now = int(time.time())
    token = jwt.encode(
        {"iss": "https://idp.example.com", "aud": "other-client", "sub": "u", "iat": now, "exp": now + 3600},
        private_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    with pytest.raises(jwt.PyJWTError):
        oidc_service.verify_id_token(
            token, jwks, audience="client-123", issuer="https://idp.example.com"
        )


def test_verify_id_token_rejects_bad_signature():
    _, jwks, kid = _generate_rsa_jwks()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    now = int(time.time())
    token = jwt.encode(
        {"iss": "https://idp.example.com", "aud": "client-123", "sub": "u", "iat": now, "exp": now + 3600},
        other_pem,
        algorithm="RS256",
        headers={"kid": kid},
    )
    with pytest.raises(jwt.PyJWTError):
        oidc_service.verify_id_token(
            token, jwks, audience="client-123", issuer="https://idp.example.com"
        )


def test_sso_config_disabled_by_default(client, monkeypatch):
    from backend.app.config import settings

    monkeypatch.setattr(settings, "SSO_ENABLED", False, raising=False)
    res = client.get("/api/v1/auth/sso/config")
    assert res.status_code == 200
    assert res.json()["enabled"] is False


def test_sso_config_enabled_returns_url(client, monkeypatch):
    from backend.app.config import settings

    monkeypatch.setattr(settings, "SSO_ENABLED", True, raising=False)
    monkeypatch.setattr(settings, "OIDC_ISSUER", "https://idp.example.com", raising=False)
    monkeypatch.setattr(settings, "OIDC_CLIENT_ID", "client-123", raising=False)
    monkeypatch.setattr(settings, "OIDC_SCOPE", "openid email", raising=False)
    monkeypatch.setattr(settings, "OIDC_REDIRECT_URI", "https://app/cb", raising=False)

    res = client.get("/api/v1/auth/sso/config")
    assert res.status_code == 200
    data = res.json()
    assert data["enabled"] is True
    assert data["authorization_url"].startswith("https://idp.example.com/authorize?")
    assert data["state"]


def test_sso_callback_rejects_bad_state(client, monkeypatch):
    from backend.app.config import settings

    monkeypatch.setattr(settings, "SSO_ENABLED", True, raising=False)
    res = client.post(
        "/api/v1/auth/sso/callback", json={"code": "abc", "state": "invalid.state"}
    )
    assert res.status_code == 400

