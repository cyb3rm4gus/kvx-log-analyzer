"""IPQualityScore IP reputation — on demand only, one credit per request (spec §3.3).

`www.` host on purpose (bare host 301s; httpx does not follow by default) and a named
User-Agent (IPQS sits behind Cloudflare, which blocks the default python-httpx UA) —
both gotchas inherited from Aphelion's `ipqs_client.py`.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)

IP_URL = "https://www.ipqualityscore.com/api/json/ip/{key}/{ip}"
ACCOUNT_URL = "https://www.ipqualityscore.com/api/json/account/{key}"
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; LogAnalyzerIPQS/1.0)", "Accept": "application/json"}
HTTP_TIMEOUT = httpx.Timeout(30.0)


class IPQSError(Exception):
    """`charged` is True when IPQS processed the request (a `success:false` answer), False when it
    never got there (transport / non-200) — only charged failures count against the day."""

    def __init__(self, message: str, *, charged: bool = False) -> None:
        super().__init__(message)
        self.charged = charged


class IPQSClient:
    def __init__(self, api_key: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.api_key = api_key
        self._transport = transport

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=HTTP_TIMEOUT, transport=self._transport,
                                 headers=HEADERS, follow_redirects=True)

    async def lookup(self, ip: str, *, user_agent: str | None = None,
                     user_language: str | None = None, strictness: int = 0) -> dict[str, Any]:
        if not self.api_key:
            raise IPQSError("IPQS_KEY is not set")
        params: dict[str, Any] = {"strictness": strictness}
        if user_agent:
            params["user_agent"] = user_agent[:512]
        if user_language:
            params["user_language"] = user_language[:64]
        try:
            async with self._client() as c:
                r = await c.get(IP_URL.format(key=self.api_key, ip=ip), params=params)
        except httpx.HTTPError as exc:
            raise IPQSError(f"transport: {exc.__class__.__name__}") from exc
        if r.status_code != 200:
            raise IPQSError(f"HTTP {r.status_code}")
        try:
            body = r.json()
        except ValueError as exc:
            raise IPQSError("non-JSON response (blocked?)") from exc
        if not body.get("success"):
            msg = body.get("message") or "success=false"
            # A rejected key or an exhausted balance is not a processed lookup: do not count it
            # against the day (seen live 2026-09-02: "Invalid or unauthorized key…").
            uncharged = any(w in msg.lower() for w in ("key", "unauthorized", "credit", "insufficient"))
            raise IPQSError(msg, charged=not uncharged)
        return body

    async def account(self) -> dict[str, Any] | None:
        """Credits/usage without spending a lookup; None when the key is unset or the call fails."""
        if not self.api_key:
            return None
        try:
            async with self._client() as c:
                r = await c.get(ACCOUNT_URL.format(key=self.api_key))
                body = r.json()
        except (httpx.HTTPError, ValueError):
            return None
        return body if body.get("success", True) else None
