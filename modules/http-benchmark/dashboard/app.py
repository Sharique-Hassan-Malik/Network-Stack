"""
Dashboard API.

Serves the benchmark results as JSON and hosts the static React UI.
Results are stored in memory and updated each time a benchmark run completes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="HTTP Performance Analyzer", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

_STATIC = Path(__file__).parent / "static"

# In-memory state updated by the benchmark runner
_state: dict = {
    "status":  "idle",
    "results": [],
    "summary": [],
    "last_run": None,
}


def update_state(results_json: list[dict], summary: list[dict]) -> None:
    import datetime
    _state["status"]   = "complete"
    _state["results"]  = results_json
    _state["summary"]  = summary
    _state["last_run"] = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).isoformat()


def set_status(status: str) -> None:
    _state["status"] = status


@app.get("/api/state")
def get_state() -> JSONResponse:
    return JSONResponse(_state)


@app.get("/api/results")
def get_results() -> JSONResponse:
    return JSONResponse(_state["results"])


@app.get("/api/summary")
def get_summary() -> JSONResponse:
    return JSONResponse(_state["summary"])


@app.get("/api/status")
def get_status() -> dict:
    return {"status": _state["status"], "last_run": _state["last_run"]}


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


if _STATIC.exists():
    app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
