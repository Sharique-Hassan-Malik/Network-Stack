"""
Test ASGI application.

Endpoints:
  GET /small          1 KB response
  GET /medium         100 KB response
  GET /large          1 MB response
  GET /resources      JSON list of N resource URLs
  GET /resource/{n}   Variable-size resource (n KB)
  GET /echo           Echo request headers as JSON
  GET /simulate/hol   Slow endpoint to demonstrate HOL blocking
"""

import asyncio
import json
import os
import time

_KB = 1024
_SMALL_BODY  = b"x" * _KB
_MEDIUM_BODY = b"x" * (100 * _KB)
_LARGE_BODY  = b"x" * (_KB * _KB)  # 1 MB


async def app(scope, receive, send):
    if scope["type"] != "http":
        return

    path   = scope["path"]
    method = scope["method"]

    if path == "/small":
        await _respond(send, 200, _SMALL_BODY, b"application/octet-stream")

    elif path == "/medium":
        await _respond(send, 200, _MEDIUM_BODY, b"application/octet-stream")

    elif path == "/large":
        await _respond(send, 200, _LARGE_BODY, b"application/octet-stream")

    elif path == "/resources":
        qs    = dict(p.split("=") for p in (scope.get("query_string", b"").decode()).split("&") if "=" in p)
        n     = int(qs.get("n", "20"))
        size  = int(qs.get("size", "10"))
        urls  = [f"/resource/{size}?id={i}" for i in range(n)]
        body  = json.dumps({"urls": urls}).encode()
        await _respond(send, 200, body, b"application/json")

    elif path.startswith("/resource/"):
        qs   = dict(p.split("=") for p in (scope.get("query_string", b"").decode()).split("&") if "=" in p)
        try:
            kb = int(path.split("/resource/")[1])
        except ValueError:
            kb = 10
        await _respond(send, 200, b"x" * (kb * _KB), b"application/octet-stream")

    elif path == "/echo":
        headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        body    = json.dumps({
            "method":      method,
            "path":        path,
            "http_version": scope.get("http_version", "?"),
            "headers":     headers,
        }).encode()
        await _respond(send, 200, body, b"application/json")

    elif path == "/simulate/hol":
        qs     = dict(p.split("=") for p in (scope.get("query_string", b"").decode()).split("&") if "=" in p)
        delay  = float(qs.get("delay", "0.1"))
        await asyncio.sleep(delay)
        await _respond(send, 200, b"done", b"text/plain")

    elif path == "/health":
        await _respond(send, 200, b"ok", b"text/plain")

    else:
        await _respond(send, 404, b"not found", b"text/plain")


async def _respond(send, status: int, body: bytes, content_type: bytes) -> None:
    await send({
        "type":    "http.response.start",
        "status":  status,
        "headers": [
            (b"content-type",   content_type),
            (b"content-length", str(len(body)).encode()),
            (b"cache-control",  b"no-store"),
            (b"x-server-time",  str(time.time()).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})
