def test_register_organization(client):
    payload = {
        "company_name": "Initech Defense",
        "domain": "initech.com",
        "full_name": "Peter Gibbons",
        "email": "peter@initech.com",
        "password": "Password1234!"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert data["email"] == "peter@initech.com"
    assert data["role"] == "admin"


def test_register_duplicate_domain(client):
    payload = {
        "company_name": "Duplicate Inc",
        "domain": "duplicate.com",
        "full_name": "John Doe",
        "email": "john1@duplicate.com",
        "password": "Password1234!"
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    payload["email"] = "john2@duplicate.com"
    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    assert "Organization domain is already registered" in res2.json()["detail"]


def test_login_success(client, test_admin_user):
    payload = {
        "email": "admin@acme.corp",
        "password": "SuperSecret123!"
    }
    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["role"] == "admin"


def test_login_wrong_password(client, test_admin_user):
    payload = {
        "email": "admin@acme.corp",
        "password": "WrongPassword!"
    }
    response = client.post("/api/v1/auth/login", json=payload)
    assert response.status_code == 401


def test_me_endpoint_authenticated(client, auth_headers):
    response = client.get("/api/v1/auth/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "admin@acme.corp"
    assert data["full_name"] == "Alice Admin"


def test_me_endpoint_unauthenticated(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_api_key_generation(client, auth_headers):
    # Create API key
    res = client.post("/api/v1/auth/api-keys", json={"name": "Agent-Host-01"}, headers=auth_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Agent-Host-01"
    assert "raw_key" in data
    assert data["raw_key"].startswith("snx_live_")

    # List API keys
    list_res = client.get("/api/v1/auth/api-keys", headers=auth_headers)
    assert list_res.status_code == 200
    keys = list_res.json()
    assert len(keys) == 1
    assert keys[0]["raw_key"] is None  # Raw key not exposed on list

