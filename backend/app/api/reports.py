from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.tenant import Tenant
from backend.app.services.report_service import (
    build_summary,
    summary_to_csv,
    summary_to_json,
)
from backend.app.utils.dependencies import get_current_tenant

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/summary")
def get_summary_report(
    format: str = Query("json", pattern="^(json|csv)$"),
    days: int = Query(30, ge=1, le=365),
    tenant: Tenant = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    """Generate a security summary report as JSON or a downloadable CSV.

    The CSV export contains the alert rows for the period; JSON returns the
    full structured summary including case and employee breakdowns.
    """
    summary = build_summary(db, tenant, days=days)

    if format == "csv":
        csv_text = summary_to_csv(summary)
        return PlainTextResponse(
            content=csv_text,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="sentinelx_report_{days}d.csv"'
            },
        )

    # JSON: return the parsed structure so FastAPI serializes it directly.
    import json

    return json.loads(summary_to_json(summary))
