PAYLOAD = {"tool": "read_file", "arguments": {"path": "../../etc/passwd"}}


def test_traversal_succeeds_vulnerable(vuln):
    r = vuln.post("/tools/call", json=PAYLOAD)
    assert r.status_code == 200
    assert "root" in r.json()["result"]


def test_traversal_blocked_hardened(hard, valid_token):
    r = hard.post(
        "/tools/call", json=PAYLOAD,
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert r.status_code == 400
    assert "traversal" in r.json()["detail"].lower()
