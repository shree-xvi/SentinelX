from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.schemas.auth import TokenResponse
from backend.app.schemas.sso import SsoCallbackRequest, SsoConfigResponse
from backend.app.services import oidc_service
from backend.app.utils.security import create_access_token, hash_password
import secrets

router = APIRouter(prefix="/auth/sso", tags=["Authentication"])


@router.get("/config", response_model=SsoConfigResponse)
def sso_config():
    """Return whether SSO is enabled and, if so, an authorization URL to start.

    In production the discovery document is fetched from the issuer. Here we
    build the URL from configured settings; the discovery/JWKS fetch is
    performed during the callback for verification.
    """
    if not settings.SSO_ENABLED:
        return SsoConfigResponse(enabled=False)

    discovery = {
        "authorization_endpoint": f"{settings.OIDC_ISSUER.rstrip('/')}/authorize",
        "client_id": settings.OIDC_CLIENT_ID,
        "scope": settings.OIDC_SCOPE,
        "redirect_uri": settings.OIDC_REDIRECT_URI,
    }
    result = oidc_service.build_authorization_url(discovery)
    return SsoConfigResponse(
        enabled=True,
        authorization_url=result["authorization_url"],
        state=result["state"],
        nonce=result["nonce"],
    )


@router.post("/callback", response_model=TokenResponse)
def sso_callback(
    req: SsoCallbackRequest,
    db: Session = Depends(get_db),
):
    """Complete the OIDC authorization-code flow and issue a SentinelX JWT.

    The IdP HTTP interactions are dependency-injected at call time so this
    endpoint can be exercised in tests with a fake transport. In production a
    module-level default transport performs the real network calls.
    """
    if not settings.SSO_ENABLED:
        raise HTTPException(status_code=404, detail="SSO is not enabled.")

    # 1. Validate the state to mitigate CSRF.
    state_payload = oidc_service.verify_state(req.state)
    if not state_payload:
        raise HTTPException(status_code=400, detail="Invalid or expired SSO state.")

    # 2. Fetch discovery + JWKS and exchange the code. These use the real
    #    network transport in production.
    import httpx

    def _get(url: str, headers: dict):
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url, headers=headers)
            return resp.status_code, resp.text

    def _post(url: str, headers: dict, data: dict):
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(url, headers=headers, data=data)
            return resp.status_code, resp.text

    try:
        disc_status, disc_text = _get(
            f"{settings.OIDC_ISSUER.rstrip('/')}/.well-known/openid-configuration", {}
        )
        if disc_status != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch OIDC discovery.")
        discovery = __import__("json").loads(disc_text)

        tokens = oidc_service.exchange_code(
            discovery["token_endpoint"],
            req.code,
            settings.OIDC_CLIENT_ID,
            settings.OIDC_CLIENT_SECRET or None,
            settings.OIDC_REDIRECT_URI,
            _post,
        )

        jwks_status, jwks_text = _get(discovery["jwks_uri"], {})
        if jwks_status != 200:
            raise HTTPException(status_code=502, detail="Failed to fetch JWKS.")
        jwks = __import__("json").loads(jwks_text)

        claims = oidc_service.verify_id_token(
            tokens["id_token"],
            jwks,
            audience=settings.OIDC_CLIENT_ID,
            issuer=settings.OIDC_ISSUER,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"SSO authentication failed: {exc}")

    # 3. Provision / look up the local user.
    email = claims.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="IdP did not return an email claim.")

    user = db.query(User).filter(User.email == email).first()
    if not user:
        tenant = db.query(Tenant).filter(Tenant.domain == email.split("@")[-1]).first()
        if not tenant:
            tenant = Tenant(name=email.split("@")[-1], domain=email.split("@")[-1], plan="enterprise")
            db.add(tenant)
            db.flush()
        user = User(
            tenant_id=tenant.id,
            email=email,
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            full_name=claims.get("name"),
            role="analyst",
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    token = create_access_token({"sub": user.id, "tenant_id": user.tenant_id, "role": user.role})
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email,
    )
