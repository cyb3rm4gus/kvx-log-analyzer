"""Fixtures: an in-memory store, a mocked Guardhouse (contract shapes from the wiki API contract),
and an app wired to both. No test touches the network."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from loganalyzer.config import Settings
from loganalyzer.db import Database
from loganalyzer.enrich.ipqs import IPQSClient
from loganalyzer.guardhouse import GuardhouseClient
from loganalyzer.jobs import JobRunner
from loganalyzer.main import create_app

U1 = "11111111-1111-4111-8111-111111111111"
U2 = "22222222-2222-4222-8222-222222222222"
U_UNKNOWN = "99999999-9999-4999-8999-999999999999"
PII_EMAIL = "secret.person@example.com"
PII_PHONE = "12345678901"

UA_CHROME_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
UA_CHROME_2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
UA_IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"


def ev(created_at: str, ip: str = "203.0.113.10", ua: str = UA_CHROME_1, session: str = "sess-aaaa-1",
       url: str = "https://platform.example/lobby", country: str = "DE", language: str = "de",
       referrer: str = "", click_id: str = "") -> dict[str, Any]:
    return {"frontend_session_uuid": session, "country": country, "language": language,
            "user_agent": ua, "click_id": click_id, "url": url, "referrer_url": referrer,
            "ip_address": ip, "created_at": created_at}


def sample_events() -> list[dict[str, Any]]:
    """Chronological; the mock serves them newest-first like the warehouse."""
    return [
        ev("2026-08-01 10:00:00"),
        ev("2026-08-01 10:05:00", url="https://platform.example/deposit?amt=10"),
        ev("2026-08-02 09:00:00", ip="198.51.100.7", session="sess-bbbb-2", ua=UA_CHROME_2),
        ev("2026-08-03 21:30:00", ip="198.51.100.7", session="sess-cccc-3", ua=UA_IPHONE, country="TR", language="tr"),
    ]


class MockGuardhouse:
    """Serves `events_by_uuid` pages for known uuids; anything else is a 404 per the contract."""

    def __init__(self, pages: dict[str, list[list[dict[str, Any]]]] | None = None) -> None:
        self.pages = pages or {}
        self.responses: dict[str, list[httpx.Response]] = {}   # scripted per-uuid responses (consumed first)
        self.calls: list[tuple[str, int]] = []
        self.ready = True
        self.raise_connect = False

    def script(self, uuid: str, *responses: httpx.Response) -> None:
        self.responses.setdefault(uuid, []).extend(responses)

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.raise_connect:
            raise httpx.ConnectError("no route to host")
        if request.url.path == "/readyz":
            return httpx.Response(200 if self.ready else 503, json={"status": "ready" if self.ready else "not_ready"})
        assert request.url.path == "/v1/query"
        assert request.headers["authorization"].startswith("Bearer ")
        body = json.loads(request.content)
        assert body["name"] == "events_by_uuid"
        uuid, page = body["params"]["uuid"], int(body["params"].get("page", 1))
        self.calls.append((uuid, page))
        scripted = self.responses.get(uuid)
        if scripted:
            return scripted.pop(0)
        if uuid not in self.pages:
            return httpx.Response(404, json={"error": {"code": "not_found", "message": "no such player", "request_id": "r1"}})
        pl = self.pages[uuid]
        events = pl[page - 1] if page <= len(pl) else []
        return httpx.Response(200, json={
            "player": {"email": PII_EMAIL, "phone": PII_PHONE, "uuid": uuid},
            "events": events, "page": page, "has_more": page < len(pl)})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)


def paged(events: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    newest_first = list(reversed(events))
    return [newest_first[i:i + size] for i in range(0, len(newest_first), size)] or [[]]


@pytest.fixture
def settings() -> Settings:
    return Settings(gh_api_url="http://gh.test", gh_token="tok", ipqs_key="", db_path=":memory:",
                    gh_concurrency=2, ready_poll_seconds=0.01, ready_poll_attempts=5, enrich=False)


@pytest.fixture
def db() -> Database:
    return Database(":memory:")


@pytest.fixture
def mock_gh() -> MockGuardhouse:
    return MockGuardhouse({U1: paged(sample_events(), 1000), U2: paged([ev("2026-07-01 00:00:00")], 1000)})


@pytest.fixture
def runner(db: Database, settings: Settings, mock_gh: MockGuardhouse) -> JobRunner:
    client = GuardhouseClient(settings.gh_api_url, settings.gh_token, transport=mock_gh.transport())
    return JobRunner(db, client, settings)


@pytest.fixture
def app(settings: Settings, db: Database, mock_gh: MockGuardhouse):
    return create_app(settings, db, gh_transport=mock_gh.transport(),
                      ipqs=IPQSClient("", transport=httpx.MockTransport(lambda r: httpx.Response(500))))


@pytest.fixture
def client(app):
    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c
