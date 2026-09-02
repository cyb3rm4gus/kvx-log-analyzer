"""IP → origin ASN + AS name via Team Cymru's DNS interface (free, keyless, their preferred path).

    <reversed-v4>.origin.asn.cymru.com  TXT → "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
    <reversed-nibbles>.origin6.asn.cymru.com (IPv6)
    AS23028.asn.cymru.com               TXT → "23028 | US | arin | 2002-01-04 | TEAM-CYMRU, US"
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Callable
from typing import Any

Resolver = Callable[[str], list[str]]


def _default_resolve(name: str) -> list[str]:
    import dns.resolver  # dnspython

    try:
        answer = dns.resolver.resolve(name, "TXT", lifetime=8.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]


def origin_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_origin(txt: str) -> dict[str, Any]:
    parts = [p.strip() for p in txt.split("|")]
    asn = parts[0].split()[0] if parts and parts[0] else None
    return {
        "asn": int(asn) if asn and asn.isdigit() else None,
        "prefix": parts[1] if len(parts) > 1 else None,
        "asn_registry": parts[3] if len(parts) > 3 else None,
    }


def parse_asname(txt: str) -> str | None:
    parts = [p.strip() for p in txt.split("|")]
    return parts[4] if len(parts) > 4 else None


class AsnLookup:
    def __init__(self, resolve: Resolver | None = None) -> None:
        self._resolve = resolve or _default_resolve
        self._names: dict[int, str | None] = {}

    async def lookup(self, ip: str) -> dict[str, Any]:
        if not ipaddress.ip_address(ip).is_global:
            return {}
        answers = await asyncio.to_thread(self._resolve, origin_name(ip))
        if not answers:
            return {"asn": None, "as_name": None}
        info = parse_origin(answers[0])
        asn = info.get("asn")
        if asn is not None:
            if asn not in self._names:
                names = await asyncio.to_thread(self._resolve, f"AS{asn}.asn.cymru.com")
                self._names[asn] = parse_asname(names[0]) if names else None
            info["as_name"] = self._names[asn]
        return info
