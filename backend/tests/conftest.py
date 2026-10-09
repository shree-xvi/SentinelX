import os
import sys
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure test DB
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["ENVIRONMENT"] = "testing"

from backend.app.database import Base, get_db
from backend.app.main import app
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.utils.security import hash_password, create_access_token

from sqlalchemy.pool import StaticPool

TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=TEST_ENGINE)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=TEST_ENGINE)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=TEST_ENGINE)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_tenant(db_session):
    tenant = Tenant(
        name="Acme Security Corp",
        domain="acme.corp",
        plan="enterprise"
    )
    db_session.add(tenant)
    db_session.commit()
    db_session.refresh(tenant)
    return tenant


@pytest.fixture
def test_admin_user(db_session, test_tenant):
    user = User(
        tenant_id=test_tenant.id,
        email="admin@acme.corp",
        hashed_password=hash_password("SuperSecret123!"),
        full_name="Alice Admin",
        role="admin",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_admin_user, test_tenant):
    token = create_access_token({
        "sub": test_admin_user.id,
        "tenant_id": test_tenant.id,
        "role": test_admin_user.role
    })
    return {"Authorization": f"Bearer {token}"}
