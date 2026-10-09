"""
Migration script: Imports legacy SentinelX alerts and investigations from Logs/ into database.
"""
import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import SessionLocal, Base, engine
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.models.alert import Alert
from backend.app.models.case import Case, CaseNote
from backend.app.models.employee import Employee
from backend.app.utils.security import hash_password
from backend.app.detection.engine import DetectionEngine


def migrate(tenant_domain: str = "default.sentinelx.local", db: SessionLocal = None):
    should_close = False
    if db is None:
        Base.metadata.create_all(bind=engine)
        db = SessionLocal()
        should_close = True

    try:
        # 1. Ensure a default tenant exists
        tenant = db.query(Tenant).filter(Tenant.domain == tenant_domain).first()
        if not tenant:
            tenant = Tenant(
                name="Legacy Workspace",
                domain=tenant_domain,
                plan="enterprise"
            )
            db.add(tenant)
            db.flush()

            # Create default admin
            admin = User(
                tenant_id=tenant.id,
                email="admin@" + tenant_domain,
                hashed_password=hash_password("admin12345!"),
                full_name="Default Administrator",
                role="admin"
            )
            db.add(admin)
            db.flush()
            print(f"[+] Created tenant '{tenant.name}' and default admin '{admin.email}'.")

        # 2. Read Logs/alerts.json
        alerts_file = PROJECT_ROOT / "Logs" / "alerts.json"
        if not alerts_file.exists():
            print(f"[-] Alerts file not found at {alerts_file}")
            return

        with alerts_file.open("r", encoding="utf-8") as f:
            legacy_alerts = json.load(f)

        # 3. Read Logs/alert_investigations.json
        inv_file = PROJECT_ROOT / "Logs" / "alert_investigations.json"
        investigations = {}
        if inv_file.exists():
            try:
                with inv_file.open("r", encoding="utf-8") as f:
                    investigations = json.load(f)
            except Exception:
                pass

        imported_alerts = 0
        imported_cases = 0

        for item in legacy_alerts:
            # Generate stable fingerprint
            alert_type = item.get("type", "UNKNOWN")
            source_ip = item.get("source_ip")
            det_at_str = item.get("detected_at")
            if det_at_str:
                try:
                    det_at = datetime.fromisoformat(det_at_str)
                except Exception:
                    det_at = datetime.now(timezone.utc)
            else:
                det_at = datetime.now(timezone.utc)

            raw_evidence = {
                "attempts": item.get("attempts"),
                "time_window_minutes": item.get("time_window_minutes"),
                "failed_attempts": item.get("failed_attempts"),
                "distinct_users": item.get("distinct_users"),
            }

            fake_alert = {
                "alert_type": alert_type,
                "source_ip": source_ip,
                "employee_id": None,
                "evidence": {"rule": alert_type}
            }
            fingerprint = DetectionEngine.compute_fingerprint(fake_alert)

            # Avoid duplicates in DB
            existing = db.query(Alert).filter(
                Alert.tenant_id == tenant.id,
                Alert.fingerprint == fingerprint,
                Alert.detected_at == det_at
            ).first()

            if not existing:
                alert = Alert(
                    tenant_id=tenant.id,
                    alert_type=alert_type,
                    severity=item.get("severity", "HIGH"),
                    risk_score=75.0 if item.get("severity") == "HIGH" else 40.0,
                    risk_level=item.get("severity", "HIGH"),
                    source_ip=source_ip,
                    fingerprint=fingerprint,
                    status="New",
                    evidence=raw_evidence,
                    detected_at=det_at
                )
                db.add(alert)
                db.flush()
                imported_alerts += 1

                # Check if this alert had investigation notes
                for inv_hash, inv_data in investigations.items():
                    if inv_data.get("notes") or inv_data.get("status") in ("Investigating", "Resolved"):
                        # Create case
                        case = Case(
                            tenant_id=tenant.id,
                            alert_id=alert.id,
                            title=f"Legacy Investigation: {alert_type} from {source_ip}",
                            description=inv_data.get("notes", ""),
                            status=inv_data.get("status", "New"),
                            priority=alert.severity
                        )
                        db.add(case)
                        db.flush()
                        imported_cases += 1
                        break

        db.commit()
        print(f"[SUCCESS] Imported {imported_alerts} legacy alerts and {imported_cases} cases into tenant '{tenant.name}'.")

    finally:
        if should_close:
            db.close()


if __name__ == "__main__":
    migrate()
