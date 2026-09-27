import time

import httpx
import jwt
import pytest

JWT_SECRET = "lab-jwt-signing-key"
AUDIENCE = "mcp-lab"


def make_token(**overrides):
    payload = {
        "sub": "test-agent",
        "aud": AUDIENCE,
        "exp": int(time.time()) + 3600,
        "scope": "tools:read",
    }
    payload.update(overrides)
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


@pytest.fixture(scope="session")
def vuln():
    return httpx.Client(base_url="http://localhost:8000", timeout=5.0)


@pytest.fixture(scope="session")
def hard():
    return httpx.Client(base_url="http://localhost:8001", timeout=5.0)


@pytest.fixture(scope="session")
def valid_token():
    return make_token()


@pytest.fixture(scope="session")
def expired_token():
    return make_token(exp=int(time.time()) - 3600)


@pytest.fixture(scope="session")
def wrong_aud_token():
    return make_token(aud="other-service")


@pytest.fixture(scope="session")
def low_scope_token():
    return make_token(scope="tools:read")


@pytest.fixture(scope="session")
def critical_token():
    return make_token(scope="tools:read tools:critical")
