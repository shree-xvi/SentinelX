from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.utils.security import hash_password, create_access_token


def test_create_and_list_employees(client, auth_headers):
    # Add employee
    emp_payload = {
        "employee_id": "EMP-1001",
        "name": "Bob Vance",
        "email": "bob@acme.corp",
        "department": "Refrigeration",
        "title": "Director"
    }
    create_res = client.post("/api/v1/employees", json=emp_payload, headers=auth_headers)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["employee_id"] == "EMP-1001"
    assert created["risk_score"] == 0.0

    # List employees
    list_res = client.get("/api/v1/employees", headers=auth_headers)
    assert list_res.status_code == 200
    employees = list_res.json()
    assert len(employees) == 1
    assert employees[0]["name"] == "Bob Vance"


def test_update_employee(client, auth_headers):
    emp_payload = {
        "employee_id": "EMP-1002",
        "name": "Pam Beesly",
        "email": "pam@acme.corp",
        "department": "Admin"
    }
    create_res = client.post("/api/v1/employees", json=emp_payload, headers=auth_headers)
    emp_id = create_res.json()["id"]

    # Update title
    update_res = client.put(f"/api/v1/employees/{emp_id}", json={"title": "Office Administrator"}, headers=auth_headers)
    assert update_res.status_code == 200
    assert update_res.json()["title"] == "Office Administrator"


def test_tenant_data_isolation(client, db_session, auth_headers):
    # Create employee in Tenant A (Acme Corp)
    client.post("/api/v1/employees", json={"employee_id": "EMP-A", "name": "Employee A"}, headers=auth_headers)

    # Create Tenant B and another admin user
    tenant_b = Tenant(name="Beta Corp", domain="beta.corp")
    db_session.add(tenant_b)
    db_session.commit()
    db_session.refresh(tenant_b)

    user_b = User(
        tenant_id=tenant_b.id,
        email="admin@beta.corp",
        hashed_password=hash_password("Pass123!"),
        role="admin"
    )
    db_session.add(user_b)
    db_session.commit()

    token_b = create_access_token({"sub": user_b.id, "tenant_id": tenant_b.id, "role": user_b.role})
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # Tenant B should see 0 employees
    list_b = client.get("/api/v1/employees", headers=headers_b)
    assert list_b.status_code == 200
    assert len(list_b.json()) == 0

