METADATA = {"tool": "fetch_url", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}}
LOOPBACK = {"tool": "fetch_url", "arguments": {"url": "http://127.0.0.1:9999/"}}


def test_ssrf_metadata_not_blocked_vulnerable(vuln):
    r = vuln.post("/tools/call", json=METADATA)
    assert r.status_code != 400  # server attempted the request rather than blocking it


def test_ssrf_metadata_blocked_hardened(hard, valid_token):
    r = hard.post(
        "/tools/call", json=METADATA,
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert r.status_code == 400
    assert "ssrf" in r.json()["detail"].lower()


def test_ssrf_loopback_not_blocked_vulnerable(vuln):
    r = vuln.post("/tools/call", json=LOOPBACK)
    assert r.status_code != 400


def test_ssrf_loopback_blocked_hardened(hard, valid_token):
    r = hard.post(
        "/tools/call", json=LOOPBACK,
        headers={"Authorization": f"Bearer {valid_token}"},
    )
    assert r.status_code == 400
    assert "ssrf" in r.json()["detail"].lower()
