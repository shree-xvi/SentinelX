def test_list_default_policies_after_registration(client):
    # Registering an org seeds default detection policies.
    payload = {
        "company_name": "Policy Corp",
        "domain": "policycorp.com",
        "full_name": "Dana Policies",
        "email": "dana@policycorp.com",
        "password": "Password1234!",
    }
    reg = client.post("/api/v1/auth/register", json=payload)
    token = reg.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/policies", headers=headers)
    assert res.status_code == 200
    policies = res.json()
    rule_types = {p["rule_type"] for p in policies}
    # Default seeding includes the core auth rules.
    assert "BRUTE_FORCE" in rule_types
    assert "SUSPICIOUS_LOGIN_AFTER_FAILURES" in rule_types
    assert "MULTI_ACCOUNT_FAILURES" in rule_types
    assert all(p["enabled"] for p in policies)


def test_create_and_update_policy(client, auth_headers):
    create_payload = {
        "name": "Custom USB Rule",
        "rule_type": "USB_DEVICE_USAGE",
        "description": "Detects USB storage mounts.",
        "severity": "HIGH",
        "enabled": True,
        "conditions": {"device_prefix": "USB"},
    }
    create_res = client.post("/api/v1/policies", json=create_payload, headers=auth_headers)
    assert create_res.status_code == 201
    policy = create_res.json()
    assert policy["name"] == "Custom USB Rule"
    assert policy["severity"] == "HIGH"
    policy_id = policy["id"]

    # Update the severity and disable it.
    update_res = client.patch(
        f"/api/v1/policies/{policy_id}",
        json={"severity": "CRITICAL", "enabled": False},
        headers=auth_headers,
    )
    assert update_res.status_code == 200
    updated = update_res.json()
    assert updated["severity"] == "CRITICAL"
    assert updated["enabled"] is False


def test_update_policy_conditions(client, auth_headers):
    # The shared test tenant is created directly (not via registration), so
    # seed a BRUTE_FORCE policy first.
    create_res = client.post(
        "/api/v1/policies",
        json={"name": "Brute Force", "rule_type": "BRUTE_FORCE", "severity": "HIGH"},
        headers=auth_headers,
    )
    assert create_res.status_code == 201
    policy_id = create_res.json()["id"]

    res = client.patch(
        f"/api/v1/policies/{policy_id}",
        json={"conditions": {"threshold": 10, "window_minutes": 2}},
        headers=auth_headers,
    )
    assert res.status_code == 200
    assert res.json()["conditions"] == {"threshold": 10, "window_minutes": 2}


def test_update_missing_policy_returns_404(client, auth_headers):
    res = client.patch(
        "/api/v1/policies/does-not-exist",
        json={"enabled": False},
        headers=auth_headers,
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_policies_require_authentication(client):
    res = client.get("/api/v1/policies")
    assert res.status_code == 401


def test_policy_creation_requires_admin(client, db_session, test_tenant):
    from backend.app.models.user import User
    from backend.app.utils.security import hash_password, create_access_token

    analyst = User(
        tenant_id=test_tenant.id,
        email="analyst@acme.corp",
        hashed_password=hash_password("Analyst123!"),
        role="analyst",
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()

    token = create_access_token({"sub": analyst.id, "tenant_id": test_tenant.id, "role": analyst.role})
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post(
        "/api/v1/policies",
        json={"name": "Nope", "rule_type": "CUSTOM"},
        headers=headers,
    )
    assert res.status_code == 403
