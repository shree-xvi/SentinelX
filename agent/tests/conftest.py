# Re-export fixtures from backend/tests/conftest.py
from backend.tests.conftest import (
    db_session,
    client,
    test_tenant,
    test_admin_user,
    auth_headers,
)

__all__ = [
    "db_session",
    "client",
    "test_tenant",
    "test_admin_user",
    "auth_headers",
]

