from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.notification import NotificationChannel, NotificationLog
from backend.app.schemas.notification import (
    NotificationChannelCreate,
    NotificationChannelResponse,
    NotificationChannelUpdate,
    NotificationLogResponse,
    TestNotificationRequest,
)
from backend.app.services.notification_service import dispatch_to_channel
from backend.app.utils.dependencies import get_current_tenant, require_role

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("/channels", response_model=List[NotificationChannelResponse])
def list_channels(
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """List configured notification channels for the organization."""
    return (
        db.query(NotificationChannel)
        .filter(NotificationChannel.tenant_id == tenant.id)
        .order_by(NotificationChannel.created_at.desc())
        .all()
    )


@router.post(
    "/channels",
    response_model=NotificationChannelResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_channel(
    req: NotificationChannelCreate,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Register a new notification channel (admin only)."""
    channel = NotificationChannel(
        tenant_id=tenant.id,
        name=req.name,
        channel_type=req.channel_type,
        target=req.target,
        min_severity=req.min_severity.upper(),
        enabled=req.enabled,
        secret=req.secret,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


@router.patch("/channels/{channel_id}", response_model=NotificationChannelResponse)
def update_channel(
    channel_id: str,
    req: NotificationChannelUpdate,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Update or toggle a notification channel (admin only)."""
    channel = (
        db.query(NotificationChannel)
        .filter(
            NotificationChannel.id == channel_id,
            NotificationChannel.tenant_id == tenant.id,
        )
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found.")

    if req.name is not None:
        channel.name = req.name
    if req.target is not None:
        channel.target = req.target
    if req.min_severity is not None:
        channel.min_severity = req.min_severity.upper()
    if req.enabled is not None:
        channel.enabled = req.enabled
    if req.secret is not None:
        channel.secret = req.secret

    db.commit()
    db.refresh(channel)
    return channel


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(
    channel_id: str,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Remove a notification channel (admin only)."""
    channel = (
        db.query(NotificationChannel)
        .filter(
            NotificationChannel.id == channel_id,
            NotificationChannel.tenant_id == tenant.id,
        )
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found.")
    db.delete(channel)
    db.commit()
    return None


@router.post("/channels/{channel_id}/test", response_model=NotificationLogResponse)
def test_channel(
    channel_id: str,
    req: TestNotificationRequest,
    current_user=Depends(require_role(["admin", "super_admin"])),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Send a test notification to verify channel connectivity (admin only)."""
    channel = (
        db.query(NotificationChannel)
        .filter(
            NotificationChannel.id == channel_id,
            NotificationChannel.tenant_id == tenant.id,
        )
        .first()
    )
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found.")

    payload = {"event": "notification.test", "message": req.message}
    log = dispatch_to_channel(db, channel, payload)
    return log


@router.get("/logs", response_model=List[NotificationLogResponse])
def list_logs(
    limit: int = 50,
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Recent outbound notification delivery attempts."""
    return (
        db.query(NotificationLog)
        .filter(NotificationLog.tenant_id == tenant.id)
        .order_by(NotificationLog.created_at.desc())
        .limit(limit)
        .all()
    )
