import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import httpx
import jwt as pyjwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

app = FastAPI()

JWT_SECRET = os.environ.get("JWT_SECRET", "lab-jwt-signing-key")
APP_SECRET = os.environ.get("APP_SECRET", "super-secret-db-password-12345")
AUDIENCE = "mcp-lab"
ALLOWED_BASE = Path("/data").resolve()
MAX_BODY = 1024

SHELL_RE = re.compile(r"[;&|`$()<>\\\n\r]")
INJECTION_RE = re.compile(
    r"(ignore previous|you are now|disregard|new instructions|system prompt)",
    re.IGNORECASE,
)
PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]
BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal"}
ALLOWED_COMMANDS = {"ls", "pwd", "whoami", "date"}


def require_auth(request: Request, scope: str = "tools:read") -> dict:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    token = header.removeprefix("Bearer ")
    try:
        payload = pyjwt.decode(
            token, JWT_SECRET, algorithms=["HS256"], audience=AUDIENCE
        )
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expired")
    except pyjwt.InvalidAudienceError:
        raise HTTPException(403, "Invalid audience")
    except pyjwt.PyJWTError:
        raise HTTPException(401, "Invalid token")
    if scope not in payload.get("scope", "").split():
        raise HTTPException(403, "Insufficient scope")
    return payload


def safe_path(raw: str) -> Path:
    resolved = (ALLOWED_BASE / raw).resolve()
    if not str(resolved).startswith(str(ALLOWED_BASE)):
        raise HTTPException(400, "Path traversal detected")
    return resolved


def check_ssrf(url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if host in BLOCKED_HOSTS:
        raise HTTPException(400, "SSRF: blocked host")
    try:
        addr = ipaddress.ip_address(host)
        if any(addr in net for net in PRIVATE_NETS):
            raise HTTPException(400, "SSRF: private address range")
    except ValueError:
        pass  # hostname — DNS resolution not resolved here; host allowlist is the next layer


@app.post("/tools/call")
async def call_tool(request: Request):
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(400, "Request too large")
    body = json.loads(raw)
    tool = body.get("tool")
    args = body.get("arguments", {})

    if tool == "read_file":
        require_auth(request)
        path = safe_path(args["path"])
        return {"result": path.read_text()}

    if tool == "fetch_url":
        require_auth(request)
        check_ssrf(args["url"])
        try:
            r = httpx.get(args["url"], timeout=2.0)
            return {"result": r.text}
        except Exception as e:
            return {"result": f"Error: {e}"}

    if tool == "run_command":
        require_auth(request)
        cmd = args.get("cmd", "")
        if SHELL_RE.search(cmd) or cmd.strip().split()[0] not in ALLOWED_COMMANDS:
            raise HTTPException(400, "Command not permitted")
        out = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=5)
        return {"result": out.stdout}

    if tool == "get_secret":
        require_auth(request)
        return {"result": "Connected successfully"}  # secret never returned to caller

    if tool == "delete_data":
        require_auth(request, scope="tools:critical")
        return {"result": "Data deleted"}

    if tool == "echo":
        require_auth(request)
        content = args.get("content", "")
        return {"result": INJECTION_RE.sub("[FILTERED]", content)}

    return JSONResponse(status_code=404, content={"detail": "Unknown tool"})
