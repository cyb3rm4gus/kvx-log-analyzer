"""Enrichment: keyless automatic (RDAP ownership, Team Cymru ASN, UA parse) and paid on demand (IPQS)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from ..config import Settings
from ..db import Database
from .asn import AsnLookup
from .rdap import RdapClient
from .ua import parse_ua

log = logging.getLogger(__name__)
Emit = Callable[[str], None] | None


class Enricher:
    """Automatic pass run after a batch: RDAP + ASN for each distinct IP not yet cached, UA parse."""

    def __init__(self, db: Database, settings: Settings, rdap: RdapClient | None = None,
                 asn: AsnLookup | None = None) -> None:
        self.db = db
        self.settings = settings
        self.rdap = rdap or RdapClient(db, min_interval=settings.rdap_min_interval)
        self.asn = asn or AsnLookup()

    async def enrich_ips(self, ips: list[str], emit: Emit = None) -> int:
        todo = self.db.ips_missing(ips)
        done = 0
        for ip in todo:
            fields: dict = {}
            try:
                fields.update(await self.rdap.lookup(ip))
            except Exception as exc:  # noqa: BLE001 — a lookup failure is a per-IP fact, not a crash
                fields["error"] = f"rdap: {exc}"
            try:
                fields.update(await self.asn.lookup(ip))
            except Exception as exc:  # noqa: BLE001
                fields["error"] = (fields.get("error") or "") + f" asn: {exc}"
            self.db.save_ip(ip, **fields)
            done += 1
            if emit and (done % 10 == 0 or done == len(todo)):
                emit(f"enrichment: {done} of {len(todo)} IPs")
        return done

    def enrich_uas(self, uas: list[str]) -> int:
        have = self.db.ua_rows(uas)
        n = 0
        for ua in dict.fromkeys(uas):
            if ua in have:
                continue
            self.db.save_ua(ua, *parse_ua(ua))
            n += 1
        return n
