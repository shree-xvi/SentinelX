def test_get_tenant_details(client, auth_headers):
    res = client.get("/api/v1/tenant", headers=auth_headers)
    assert res.status_code == 200
    tenant = res.json()
    assert tenant["domain"] == "acme.corp"
    assert tenant["name"] == "Acme Security Corp"
    # Business hours default to 09:00 - 18:00.
    assert tenant["business_hours_start"] == 9
    assert tenant["business_hours_end"] == 18
    assert "plan" in tenant
    assert "timezone" in tenant


def test_update_tenant_settings(client, auth_headers):
    res = client.put(
        "/api/v1/tenant",
        json={
            "name": "Acme Security Corp International",
            "business_hours_start": 8,
            "business_hours_end": 20,
            "timezone": "America/New_York",
        },
        headers=auth_headers,
    )
    assert res.status_code == 200
    tenant = res.json()
    assert tenant["name"] == "Acme Security Corp International"
    assert tenant["business_hours_start"] == 8
    assert tenant["business_hours_end"] == 20
    assert tenant["timezone"] == "America/New_York"


def test_update_tenant_partial(client, auth_headers):
    # Only updating timezone should leave other fields untouched.
    client.put("/api/v1/tenant", json={"timezone": "Europe/London"}, headers=auth_headers)
    res = client.put("/api/v1/tenant", json={"business_hours_start": 7}, headers=auth_headers)
    assert res.status_code == 200
    tenant = res.json()
    assert tenant["business_hours_start"] == 7
    assert tenant["timezone"] == "Europe/London"


def test_update_tenant_rejects_out_of_range_hours(client, auth_headers):
    res = client.put(
        "/api/v1/tenant",
        json={"business_hours_start": 24},
        headers=auth_headers,
    )
    assert res.status_code == 422


def test_tenant_requires_authentication(client):
    res = client.get("/api/v1/tenant")
    assert res.status_code == 401


def test_tenant_settings_update_requires_admin(client, db_session, test_tenant):
    from backend.app.models.user import User
    from backend.app.utils.security import hash_password, create_access_token

    analyst = User(
        tenant_id=test_tenant.id,
        email="viewer@acme.corp",
        hashed_password=hash_password("Viewer123!"),
        role="analyst",
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()

    token = create_access_token({"sub": analyst.id, "tenant_id": test_tenant.id, "role": analyst.role})
    headers = {"Authorization": f"Bearer {token}"}

    # Read is allowed for any authenticated user.
    read_res = client.get("/api/v1/tenant", headers=headers)
    assert read_res.status_code == 200

    # But updates require admin.
    write_res = client.put("/api/v1/tenant", json={"timezone": "UTC"}, headers=headers)
    assert write_res.status_code == 403
