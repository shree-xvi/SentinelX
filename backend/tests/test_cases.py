def test_create_and_update_case(client, auth_headers):
    # 1. Create a case
    payload = {
        "title": "Investigate Unauthorized Off-Hours Access",
        "description": "User logged in at 03:00 from external IP",
        "priority": "HIGH"
    }
    create_res = client.post("/api/v1/cases", json=payload, headers=auth_headers)
    assert create_res.status_code == 201
    case = create_res.json()
    assert case["title"] == payload["title"]
    assert case["status"] == "New"
    case_id = case["id"]

    # 2. Add an investigation note
    note_payload = {
        "note": "Contacted user to verify whether they were traveling.",
        "action_type": "comment"
    }
    note_res = client.post(f"/api/v1/cases/{case_id}/notes", json=note_payload, headers=auth_headers)
    assert note_res.status_code == 201
    assert note_res.json()["note"] == note_payload["note"]

    # 3. Update status to Investigating, then Resolved
    update_res = client.patch(f"/api/v1/cases/{case_id}", json={"status": "Resolved"}, headers=auth_headers)
    assert update_res.status_code == 200
    updated_case = update_res.json()
    assert updated_case["status"] == "Resolved"
    assert updated_case["resolved_at"] is not None

    # 4. Fetch full case details and verify audit trail
    get_res = client.get(f"/api/v1/cases/{case_id}", headers=auth_headers)
    assert get_res.status_code == 200
    case_detail = get_res.json()
    assert len(case_detail["notes"]) >= 2  # creation note + custom note + status update note

