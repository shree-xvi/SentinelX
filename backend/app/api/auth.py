from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.models.api_key import ApiKey
from backend.app.models.policy import Policy
from backend.app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    UserResponse,
    ApiKeyCreate,
    ApiKeyResponse
)
from backend.app.utils.security import (
    hash_password,
    verify_password,
    create_access_token,
    generate_api_key
)
from backend.app.utils.dependencies import get_current_user, get_current_tenant, require_role

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register_organization(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new tenant organization along with the initial admin user.
    Also provisions default threat detection policies for the tenant.
    """
    # Check if domain or email already registered
    if db.query(Tenant).filter(Tenant.domain == req.domain).first():
        raise HTTPException(status_code=400, detail="Organization domain is already registered.")

    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(status_code=400, detail="User email is already registered.")

    # Create tenant
    tenant = Tenant(
        name=req.company_name,
        domain=req.domain,
        plan="enterprise",
    )
    db.add(tenant)
    db.flush()

    # Create admin user
    user = User(
        tenant_id=tenant.id,
        email=req.email,
        hashed_password=hash_password(req.password),
        full_name=req.full_name,
        role="admin",
        is_active=True
    )
    db.add(user)

    # Seed default policies
    default_policies = [
        Policy(
            tenant_id=tenant.id,
            name="Brute Force Detection",
            rule_type="BRUTE_FORCE",
            description="Detects rapid successive authentication failures.",
            severity="HIGH",
            enabled=True,
            conditions={"threshold": 5, "window_minutes": 5}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Suspicious Login After Failures",
            rule_type="SUSPICIOUS_LOGIN_AFTER_FAILURES",
            description="Detects successful authentication immediately after failed attempts.",
            severity="HIGH",
            enabled=True,
            conditions={"min_failures": 3, "window_minutes": 5}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Multi-Account Credential Spraying",
            rule_type="MULTI_ACCOUNT_FAILURES",
            description="Detects failed logins against multiple accounts from a single IP.",
            severity="HIGH",
            enabled=True,
            conditions={"min_distinct_users": 3, "window_minutes": 5}
        ),
        Policy(
            tenant_id=tenant.id,
            name="After-Hours User Activity",
            rule_type="AFTER_HOURS_ACCESS",
            description="Identifies access attempts outside configured business hours or on weekends.",
            severity="MEDIUM",
            enabled=True,
            conditions={"business_hours_start": 9, "business_hours_end": 18, "allow_weekends": False}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Impossible Geolocation Travel",
            rule_type="IMPOSSIBLE_TRAVEL",
            description="Flags concurrent or sequential logins from distant geographic locations.",
            severity="CRITICAL",
            enabled=True,
            conditions={"max_speed_mph": 500, "max_window_hours": 6}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Data Exfiltration Threshold",
            rule_type="DATA_EXFILTRATION",
            description="Detects high volume data downloads or cloud transfers.",
            severity="HIGH",
            enabled=True,
            conditions={"byte_threshold": 50 * 1024 * 1024, "count_threshold": 20, "window_minutes": 15}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Mass File Operations Spikes",
            rule_type="MASS_FILE_OPERATIONS",
            description="Monitors bulk file deletes, renames, and mass modifications.",
            severity="HIGH",
            enabled=True,
            conditions={"threshold": 30, "window_minutes": 10}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Unauthorized USB Storage Usage",
            rule_type="USB_DEVICE_USAGE",
            description="Alerts on connection of unauthorized removable USB storage devices.",
            severity="HIGH",
            enabled=True,
            conditions={"allowed_device_ids": []}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Privilege Escalation Detection",
            rule_type="PRIVILEGE_ESCALATION",
            description="Alerts on unauthorized promotion to administrative or root privileges.",
            severity="CRITICAL",
            enabled=True,
            conditions={"approved_admin_users": []}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Abnormal Sensitive Resource Access",
            rule_type="ABNORMAL_RESOURCE_ACCESS",
            description="Flags access to restricted folders like /confidential, /payroll, and credentials.",
            severity="HIGH",
            enabled=True,
            conditions={}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Shadow IT & Unapproved Cloud Services",
            rule_type="SHADOW_IT_USAGE",
            description="Detects usage of unapproved file hosting, pastebins, or anonymizing VPNs.",
            severity="MEDIUM",
            enabled=True,
            conditions={}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Anomalous Outbound Email Activity",
            rule_type="ANOMALOUS_EMAIL_ACTIVITY",
            description="Monitors large email attachments or emails sent to personal accounts.",
            severity="HIGH",
            enabled=True,
            conditions={"attachment_limit_bytes": 10 * 1024 * 1024}
        ),
        Policy(
            tenant_id=tenant.id,
            name="Pre-Departure Flight Risk Signals",
            rule_type="FLIGHT_RISK_SIGNALS",
            description="Identifies job search activity or resume builders during working hours.",
            severity="MEDIUM",
            enabled=True,
            conditions={}
        ),
    ]
    for pol in default_policies:
        db.add(pol)

    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.id, "tenant_id": tenant.id, "role": user.role})
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        tenant_id=tenant.id,
        role=user.role,
        email=user.email
    )


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate with email and password, returning a JWT token."""
    user = db.query(User).filter(User.email == req.email).first()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is inactive.")

    token = create_access_token({"sub": user.id, "tenant_id": user.tenant_id, "role": user.role})
    return TokenResponse(
        access_token=token,
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
        email=user.email
    )


@router.get("/me", response_model=UserResponse)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get profile information for the authenticated user."""
    return current_user


@router.post("/api-keys", response_model=ApiKeyResponse, status_code=status.HTTP_201_CREATED)
def create_tenant_api_key(
    req: ApiKeyCreate,
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """
    Generate an API key for enrollment of agents or automated collectors.
    The secret raw key is returned ONLY once in this response.
    """
    raw_key, prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        tenant_id=tenant.id,
        name=req.name,
        key_prefix=prefix,
        key_hash=key_hash,
        is_active=True
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    return ApiKeyResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        created_at=api_key.created_at.isoformat(),
        raw_key=raw_key
    )


@router.get("/api-keys", response_model=List[ApiKeyResponse])
def list_tenant_api_keys(
    current_user: User = Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """List registered API keys for the current organization."""
    keys = db.query(ApiKey).filter(ApiKey.tenant_id == tenant.id).all()
    return [
        ApiKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            created_at=k.created_at.isoformat(),
            raw_key=None
        )
        for k in keys
    ]

