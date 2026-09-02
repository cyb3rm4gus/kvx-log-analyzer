"""Guardhouse client — `events_by_uuid` only, PII stripped at this boundary.

Shape copied from Aphelion's `guardhouse_client.py` (error classes, 429/503 mapping);
contract per wiki `guardhouse_api-contract` (POST /v1/query, 1 000 events/page, DESC).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import UTC, datetime
from typing import Any

import httpx

log = logging.getLogger(__name__)

PAGE_SIZE = 1000
HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=90.0, write=10.0, pool=10.0)
#: A page is unbounded in bytes on Guardhouse's side (scale-audit finding H2). This is our own
#: ceiling: past it the page is abandoned as an upstream error instead of being materialised.
MAX_PAGE_BYTES = 64 * 1024 * 1024
EVENT_KEYS = (
    "frontend_session_uuid", "country", "language", "user_agent", "click_id",
    "url", "referrer_url", "ip_address", "created_at",
)


class GuardhouseError(Exception):
    """Base; `code` is the contract's error code when one was returned."""

    def __init__(self, message: str, *, code: str | None = None, status: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status


class NotFound(GuardhouseError):
    """404 — the uuid is unknown to the players store (per-uuid status, never a batch failure)."""


class AuthError(GuardhouseError):
    """401 / 403 — the token is wrong; the whole batch stops."""


class InvalidParam(GuardhouseError):
    """400 — a uuid the validator let through; record and continue."""


class Desync(GuardhouseError):
    """500 source_desync — a player row with no events; 'no events', continue."""


class Unavailable(GuardhouseError):
    """429 rate_limited / 503 overloaded — back off for `retry_after` seconds."""

    def __init__(self, message: str, *, retry_after: float | None = None, **kw: Any):
        super().__init__(message, **kw)
        self.retry_after = retry_after


class Upstream(GuardhouseError):
    """502 / 504, a read timeout, or an oversized page — Guardhouse's side; retry 3× with backoff."""


class ConnectionLost(GuardhouseError):
    """Transport failure reaching Guardhouse: the analyst's VPN, not Guardhouse. The job pauses."""


@dataclass(frozen=True)
class EventsPage:
    events: list[dict[str, Any]]
    page: int
    has_more: bool


def strip_pii(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only the nine event columns. `player` (email/phone) is dropped here and never
    returned — the store's insert refuses any dict carrying `email`/`phone` as a second belt."""
    out = []
    for e in body.get("events") or []:
        out.append({k: e.get(k) for k in EVENT_KEYS})
    return out


class GuardhouseClient:
    def __init__(self, base_url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None):
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._transport = transport

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=HTTP_TIMEOUT, transport=self._transport)

    async def ready(self) -> bool:
        try:
            async with self._client() as c:
                r = await c.get(f"{self.base_url}/readyz")
                return r.status_code == 200
        except httpx.HTTPError:
            return False

    async def events_page(self, uuid: str, page: int = 1) -> EventsPage:
        payload = {"name": "events_by_uuid", "params": {"uuid": uuid, "page": int(page)}}
        headers = {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json",
                   "Accept": "application/json"}
        try:
            async with self._client() as c, c.stream("POST", f"{self.base_url}/v1/query",
                                                      json=payload, headers=headers) as resp:
                status = resp.status_code
                if status == 200:
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in resp.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_PAGE_BYTES:
                            raise Upstream(f"page {page} exceeds {MAX_PAGE_BYTES >> 20} MiB — abandoned "
                                           "(Guardhouse finding H2)", status=200)
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                else:
                    raw = await resp.aread()
        except (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout) as exc:
            # Guardhouse answered the connection but not the page: its side (a slow full scan or
            # an H2-sized page), not the analyst's VPN.
            raise Upstream(f"Guardhouse timed out on page {page}: {exc.__class__.__name__}") from exc
        except httpx.HTTPError as exc:  # connect errors, resets — the analyst's side
            raise ConnectionLost(f"Guardhouse unreachable: {exc.__class__.__name__}") from exc
        if status == 200:
            try:
                body = json.loads(raw)
            except ValueError as exc:
                raise Upstream(f"page {page}: non-JSON 200 body") from exc
            if not isinstance(body, dict):
                raise Upstream(f"page {page}: unexpected JSON shape")
            return EventsPage(events=strip_pii(body), page=int(body.get("page") or page),
                              has_more=bool(body.get("has_more")))
        code, message = _error(status, raw)
        if status == 404:
            raise NotFound(message, code=code, status=status)
        if status in (401, 403):
            raise AuthError(message, code=code, status=status)
        if status == 400:
            raise InvalidParam(message, code=code, status=status)
        if status in (429, 503):
            raise Unavailable(message, code=code, status=status, retry_after=_retry_after(resp.headers))
        if status in (502, 504):
            raise Upstream(message, code=code, status=status)
        if status == 500 and code == "source_desync":
            raise Desync(message, code=code, status=status)
        raise GuardhouseError(message, code=code, status=status)


def _error(status: int, raw: bytes) -> tuple[str | None, str]:
    try:
        body = json.loads(raw)
    except ValueError:
        return None, f"{status}: {raw[:200]!r}"
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return None, f"{status}: {str(body)[:200]}"
    return err.get("code"), f"{status} {err.get('code') or ''}: {err.get('message') or ''}".strip()


def _retry_after(headers: httpx.Headers) -> float | None:
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        pass
    try:  # HTTP-date form
        when = parsedate_to_datetime(raw)
        return max(0.0, (when - datetime.now(UTC)).total_seconds())
    except (TypeError, ValueError):
        return None
