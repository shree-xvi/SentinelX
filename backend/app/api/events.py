from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.models.event import Event
from backend.app.schemas.event import EventCreate, BatchEventCreate, EventResponse
from backend.app.schemas.alert import AlertResponse
from backend.app.services.event_processor import process_events
from backend.app.utils.dependencies import get_tenant_from_api_key_or_user, get_current_tenant

router = APIRouter(prefix="/events", tags=["Event Ingestion & Audit Logs"])


@router.post("", response_model=List[AlertResponse], status_code=status.HTTP_201_CREATED)
def ingest_single_event(
    event: EventCreate,
    tenant: Tenant = Depends(get_tenant_from_api_key_or_user),
    db: Session = Depends(get_db)
):
    """
    Ingest a single security or telemetry event.
    Triggers real-time threat detection and returns any newly raised alerts.
    """
    alerts = process_events(db, tenant.id, [event])
    return alerts


@router.post("/batch", response_model=List[AlertResponse], status_code=status.HTTP_201_CREATED)
def ingest_batch_events(
    batch: BatchEventCreate,
    tenant: Tenant = Depends(get_tenant_from_api_key_or_user),
    db: Session = Depends(get_db)
):
    """
    Ingest a batch of up to 1,000 telemetry events (e.g., from an endpoint agent).
    Evaluates detection rules against recent timeline and returns generated alerts.
    """
    alerts = process_events(db, tenant.id, batch.events)
    return alerts


@router.get("", response_model=List[EventResponse])
def query_events(
    event_type: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db)
):
    """Query stored events for audit trail and investigation."""
    query = db.query(Event).filter(Event.tenant_id == tenant.id)

    if event_type:
        query = query.filter(Event.event_type == event_type)
    if username:
        query = query.filter(Event.username == username)

    events = query.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()
    return events

