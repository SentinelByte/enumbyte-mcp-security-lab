# EnumByte MCP Security Test Lab

Companion to [MCP Server Security: What Most Implementations Get Wrong](https://enumbyte.com) on [EnumByte](https://enumbyte.com).

A minimal intentionally-vulnerable MCP server and a hardened version, side by side. Each of the 11 attack scenarios from the article has a runnable test that proves the flaw on the vulnerable server and the fix on the hardened one.

> **Warning:** The vulnerable server is intentionally insecure. Run it only inside Docker. Never expose port 8000 to the internet.

## Run

```bash
docker compose up -d
pip install -r tests/requirements.txt
pytest tests/ -v
```

## What the tests cover

| Scenario | Test file |
|---|---|
| Unauthenticated access, expired token, wrong audience, insufficient scope | `test_auth.py` |
| Path traversal | `test_path_traversal.py` |
| SSRF | `test_ssrf.py` |
| Command injection, prompt injection | `test_injection.py` |
| Oversized input, credential in response, excessive tool access | `test_validation.py` |

## Ports

| Port | Server |
|---|---|
| `localhost:8000` | Vulnerable — attacks succeed |
| `localhost:8001` | Hardened — attacks are blocked |

## How the tests work

Each test runs the same attack against both servers. On the vulnerable server the test asserts the attack *succeeds* (proving the flaw exists). On the hardened server the test asserts the attack *fails* (proving the fix works).

```
pytest tests/test_auth.py -v

tests/test_auth.py::test_unauthenticated_passes_vulnerable   PASSED
tests/test_auth.py::test_unauthenticated_blocked_hardened    PASSED
...
```
