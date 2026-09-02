"""FastAPI application factory (served as `uvicorn loganalyzer.main:create_app --factory`)."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .config import Settings
from .db import Database
from .enrich import Enricher
from .enrich.ipqs import IPQSClient
from .guardhouse import GuardhouseClient
from .jobs import JobRunner
from .web.routes import router

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"
#: Loopback only — the compose file binds 127.0.0.1 and there is no auth (spec §4.3).
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def _request_host(request: Request) -> str:
    raw = (request.headers.get("host") or "").strip().lower()
    if raw.startswith("["):
        return raw.partition("]")[0].lstrip("[")
    return raw.partition(":")[0]


def create_app(settings: Settings | None = None, db: Database | None = None,
               gh_transport: httpx.AsyncBaseTransport | None = None,
               enricher: Enricher | None = None,
               ipqs: IPQSClient | None = None) -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = settings or Settings.from_env()
    db = db or Database(settings.db_path)
    client = GuardhouseClient(settings.gh_api_url, settings.gh_token, transport=gh_transport)
    enricher = enricher or (Enricher(db, settings) if settings.enrich else None)

    app = FastAPI(title="loganalyzer", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.db = db
    app.state.guardhouse = client
    app.state.runner = JobRunner(db, client, settings, enricher)
    app.state.ipqs = ipqs or IPQSClient(settings.ipqs_key)
    app.state.ipqs_runs = {}
    app.state.ipqs_lock = asyncio.Lock()
    app.state.ipqs_account_cache = None
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)

    if not settings.gh_token:
        log.warning("GH_TOKEN is empty — every Guardhouse call will be rejected (401)")
    if not settings.ipqs_key:
        log.warning("IPQS_KEY is empty — the IPQS button is disabled")

    @app.middleware("http")
    async def guard_host(request: Request, call_next: Any) -> Response:
        if _request_host(request) not in LOOPBACK_HOSTS:
            return JSONResponse({"detail": "loopback only"}, status_code=400)
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        )
        return response

    return app
