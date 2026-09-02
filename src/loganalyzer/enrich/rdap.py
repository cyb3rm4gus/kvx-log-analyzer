"""RDAP: IANA bootstrap (RFC 9224) → RIR → `ip/<addr>` network object (RFC 9083).

Keyless. The bootstrap file is cached in the store for 7 days ("clients SHOULD NOT fetch
the registry on every RDAP request"). One request per second per registry (spec §3.1);
429 honours Retry-After once, then the IP is recorded as an error and moved past.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from ..db import Database

log = logging.getLogger(__name__)

IANA_BOOTSTRAP = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}
BOOTSTRAP_TTL_DAYS = 7
HTTP_TIMEOUT = httpx.Timeout(20.0)
HEADERS = {"Accept": "application/rdap+json, application/json", "User-Agent": "loganalyzer/0.1 (+local analyst tool)"}


class RdapClient:
    def __init__(self, db: Database, *, min_interval: float = 1.0,
                 transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.db = db
        self.min_interval = min_interval
        self._transport = transport
        self._services: dict[int, list[tuple[Any, str]]] = {}
        self._last: dict[str, float] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=HTTP_TIMEOUT, transport=self._transport,
                                 headers=HEADERS, follow_redirects=True)

    # -- bootstrap -----------------------------------------------------------
    async def bootstrap(self, version: int) -> list[tuple[Any, str]]:
        if version in self._services:
            return self._services[version]
        key = f"rdap_bootstrap_v{version}"
        cached = self.db.kv_get(key)
        raw: str | None = None
        if cached:
            value, updated = cached
            age = datetime.now(UTC) - datetime.strptime(updated, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            if age.days < BOOTSTRAP_TTL_DAYS:
                raw = value
        if raw is None:
            async with self._client() as c:
                r = await c.get(IANA_BOOTSTRAP[version])
                r.raise_for_status()
                raw = r.text
            self.db.kv_set(key, raw)
        self._services[version] = parse_bootstrap(raw)
        return self._services[version]

    async def registry_for(self, ip: str) -> str | None:
        addr = ipaddress.ip_address(ip)
        best: tuple[int, str] | None = None
        for net, base in await self.bootstrap(addr.version):
            if addr in net and (best is None or net.prefixlen > best[0]):
                best = (net.prefixlen, base)
        return best[1] if best else None

    # -- lookup -------------------------------------------------------------
    async def _throttle(self, base: str) -> None:
        lock = self._locks.setdefault(base, asyncio.Lock())
        async with lock:
            wait = self._last.get(base, 0.0) + self.min_interval - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            self._last[base] = time.monotonic()

    async def lookup(self, ip: str) -> dict[str, Any]:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global:
            return {"rdap_registry": None, "net_name": "private/reserved", "error": None}
        base = await self.registry_for(ip)
        if not base:
            return {"error": "rdap: no registry in IANA bootstrap"}
        url = f"{base}ip/{ip}"
        async with self._client() as c:
            for attempt in (1, 2):
                await self._throttle(base)
                r = await c.get(url)
                if r.status_code == 429 and attempt == 1:
                    retry = r.headers.get("Retry-After")
                    await asyncio.sleep(min(float(retry) if retry and retry.isdigit() else 5.0, 60.0))
                    continue
                break
        if r.status_code != 200:
            return {"rdap_registry": base, "error": f"rdap: HTTP {r.status_code}"}
        obj = r.json()
        parsed = parse_network(obj)
        parsed["rdap_registry"] = base
        parsed["rdap_json"] = json.dumps(obj)[:200_000]
        return parsed


def parse_bootstrap(raw: str) -> list[tuple[Any, str]]:
    data = json.loads(raw)
    out: list[tuple[Any, str]] = []
    for entry in data.get("services", []):
        cidrs, urls = entry[0], entry[1]
        https = [u for u in urls if u.startswith("https://")] or urls
        if not https:
            continue
        base = https[0] if https[0].endswith("/") else https[0] + "/"
        for cidr in cidrs:
            out.append((ipaddress.ip_network(cidr, strict=False), base))
    return out


def _vcard(entity: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    vc = entity.get("vcardArray")
    if isinstance(vc, list) and len(vc) == 2 and isinstance(vc[1], list):
        for item in vc[1]:
            if isinstance(item, list) and len(item) >= 4 and isinstance(item[0], str):
                name, value = item[0].lower(), item[3]
                if name in ("fn", "email", "org") and name not in out and isinstance(value, str):
                    out[name] = value
    return out


def _walk_entities(entities: list[dict[str, Any]], depth: int = 0):
    for ent in entities or []:
        yield ent
        if depth < 2:
            yield from _walk_entities(ent.get("entities") or [], depth + 1)


def parse_network(obj: dict[str, Any]) -> dict[str, Any]:
    registrant = abuse = None
    for ent in _walk_entities(obj.get("entities") or []):
        roles = [r.lower() for r in ent.get("roles") or []]
        card = _vcard(ent)
        if "registrant" in roles and not registrant:
            registrant = card.get("fn") or card.get("org") or ent.get("handle")
        if "abuse" in roles and not abuse:
            abuse = card.get("email")
    start, end = obj.get("startAddress"), obj.get("endAddress")
    return {
        "net_name": obj.get("name"),
        "net_range": f"{start} - {end}" if start and end else None,
        "net_type": obj.get("type"),
        "net_country": obj.get("country"),
        "registrant": registrant,
        "abuse_email": abuse,
        "error": None,
    }
