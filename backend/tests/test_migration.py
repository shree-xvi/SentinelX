from backend.scripts.migrate_legacy_alerts import migrate
from backend.app.models.tenant import Tenant
from backend.app.models.alert import Alert


def test_legacy_alerts_migration(db_session):
    migrate(tenant_domain="test.migrated.corp", db=db_session)

    # Verify tenant was created
    tenant = db_session.query(Tenant).filter(Tenant.domain == "test.migrated.corp").first()
    assert tenant is not None

    # Verify alerts were imported
    alerts = db_session.query(Alert).filter(Alert.tenant_id == tenant.id).all()
    assert len(alerts) > 0
