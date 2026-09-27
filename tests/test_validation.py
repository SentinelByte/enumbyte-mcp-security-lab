BIG_PAYLOAD = {"tool": "echo", "arguments": {"content": "A" * 10_000}}
SECRET_PAYLOAD = {"tool": "get_secret", "arguments": {}}
DELETE_PAYLOAD = {"tool": "delete_data", "arguments": {}}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# oversized input

def test_oversized_input_passes_vulnerable(vuln):
    assert vuln.post("/tools/call", json=BIG_PAYLOAD).status_code == 200


def test_oversized_input_blocked_hardened(hard, valid_token):
    r = hard.post("/tools/call", json=BIG_PAYLOAD, headers=bearer(valid_token))
    assert r.status_code == 400


# credential in response

def test_credential_exposed_vulnerable(vuln):
    r = vuln.post("/tools/call", json=SECRET_PAYLOAD)
    assert r.status_code == 200
    assert "super-secret-db-password-12345" in r.json()["result"]


def test_credential_redacted_hardened(hard, valid_token):
    r = hard.post("/tools/call", json=SECRET_PAYLOAD, headers=bearer(valid_token))
    assert r.status_code == 200
    assert "super-secret-db-password" not in r.json()["result"]


# excessive tool access — critical tool reachable without critical scope

def test_critical_tool_no_scope_passes_vulnerable(vuln, low_scope_token):
    r = vuln.post("/tools/call", json=DELETE_PAYLOAD, headers=bearer(low_scope_token))
    assert r.status_code == 200


def test_critical_tool_no_scope_blocked_hardened(hard, low_scope_token):
    r = hard.post("/tools/call", json=DELETE_PAYLOAD, headers=bearer(low_scope_token))
    assert r.status_code == 403


def test_critical_tool_with_scope_allowed_hardened(hard, critical_token):
    r = hard.post("/tools/call", json=DELETE_PAYLOAD, headers=bearer(critical_token))
    assert r.status_code == 200
