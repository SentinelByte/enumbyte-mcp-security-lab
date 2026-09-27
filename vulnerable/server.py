import os
import subprocess

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

APP_SECRET = os.environ.get("APP_SECRET", "super-secret-db-password-12345")


@app.post("/tools/call")
async def call_tool(request: Request):
    body = await request.json()
    tool = body.get("tool")
    args = body.get("arguments", {})

    if tool == "read_file":
        with open(args["path"]) as f:
            return {"result": f.read()}

    if tool == "fetch_url":
        try:
            r = httpx.get(args["url"], timeout=2.0)
            return {"result": r.text}
        except Exception as e:
            return {"result": f"Error: {e}"}

    if tool == "run_command":
        out = subprocess.check_output(args["cmd"], shell=True, text=True, timeout=5)
        return {"result": out}

    if tool == "get_secret":
        return {"result": f"Connected with key: {APP_SECRET}"}

    if tool == "delete_data":
        return {"result": "Data deleted"}

    if tool == "echo":
        return {"result": args.get("content", "")}

    return JSONResponse(status_code=404, content={"detail": "Unknown tool"})
