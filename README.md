# EnumByte MCP Security Test Lab

[![CI](https://github.com/SentinelByte/enumbyte-mcp-security-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SentinelByte/enumbyte-mcp-security-lab/actions/workflows/ci.yml)

Companion to [MCP Server Security: What Most Implementations Get Wrong](https://enumbyte.com) on [EnumByte](https://enumbyte.com).

The article makes claims about how MCP servers fail. This lab lets you verify them. Each of the 11 attack scenarios has a runnable test that proves the flaw on an intentionally-vulnerable server and the fix on a hardened one — so you don't have to take anyone's word for it.

This is not a training environment or a framework to build on. It is a verification tool: read the article, run the lab, inspect the code, understand why each fix works.

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
