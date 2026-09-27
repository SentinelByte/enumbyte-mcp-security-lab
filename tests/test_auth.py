TOOL = {"tool": "echo", "arguments": {"content": "hello"}}
DELETE = {"tool": "delete_data", "arguments": {}}


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# unauthenticated access

def test_unauthenticated_passes_vulnerable(vuln):
    assert vuln.post("/tools/call", json=TOOL).status_code == 200


def test_unauthenticated_blocked_hardened(hard):
    assert hard.post("/tools/call", json=TOOL).status_code == 401


# expired token

def test_expired_token_passes_vulnerable(vuln, expired_token):
    assert vuln.post("/tools/call", json=TOOL, headers=bearer(expired_token)).status_code == 200


def test_expired_token_blocked_hardened(hard, expired_token):
    assert hard.post("/tools/call", json=TOOL, headers=bearer(expired_token)).status_code == 401


# wrong token audience

def test_wrong_aud_passes_vulnerable(vuln, wrong_aud_token):
    assert vuln.post("/tools/call", json=TOOL, headers=bearer(wrong_aud_token)).status_code == 200


def test_wrong_aud_blocked_hardened(hard, wrong_aud_token):
    assert hard.post("/tools/call", json=TOOL, headers=bearer(wrong_aud_token)).status_code == 403


# insufficient scope — low-scope token calling a critical-tier tool

def test_low_scope_passes_vulnerable(vuln, low_scope_token):
    assert vuln.post("/tools/call", json=DELETE, headers=bearer(low_scope_token)).status_code == 200


def test_low_scope_blocked_hardened(hard, low_scope_token):
    assert hard.post("/tools/call", json=DELETE, headers=bearer(low_scope_token)).status_code == 403
