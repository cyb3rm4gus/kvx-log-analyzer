import json

import httpx
import pytest

from loganalyzer.config import Settings
from loganalyzer.db import Database
from loganalyzer.enrich import Enricher
from loganalyzer.enrich.asn import AsnLookup, origin_name, parse_asname, parse_origin
from loganalyzer.enrich.ipqs import IPQSClient, IPQSError
from loganalyzer.enrich.rdap import RdapClient, parse_bootstrap, parse_network
from loganalyzer.enrich.ua import describe, parse_ua, ua_change
from tests.conftest import UA_CHROME_1, UA_CHROME_2, UA_IPHONE

BOOTSTRAP = json.dumps({"version": "1.0", "publication": "2019-06-07", "services": [
    [["8.0.0.0/8", "198.51.0.0/16"], ["https://rdap.arin.net/registry/", "http://rdap.arin.net/registry/"]],
    [["2.0.0.0/8", "198.51.100.0/24"], ["https://rdap.db.ripe.net/"]],
]})

# Shape of a live ARIN answer for 8.8.8.8 (research 2026-09-02): handle, name, type, entities w/ vcards
ARIN_8888 = {
    "objectClassName": "ip network", "handle": "NET-8-8-8-0-2", "startAddress": "8.8.8.0",
    "endAddress": "8.8.8.255", "ipVersion": "v4", "name": "GOGL", "type": "DIRECT ALLOCATION",
    "parentHandle": "NET-8-0-0-0-0", "country": None,
    "entities": [
        {"handle": "GOGL", "roles": ["registrant"],
         "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"], ["kind", {}, "text", "org"]]],
         "entities": [{"handle": "ABUSE5250-ARIN", "roles": ["abuse"],
                       "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]}]},
    ],
}


def test_bootstrap_longest_prefix():
    services = parse_bootstrap(BOOTSTRAP)
    assert len(services) == 4
    assert all(base.endswith("/") and base.startswith("https://") for _, base in services)


async def test_registry_for_prefers_most_specific(db: Database):
    db.kv_set("rdap_bootstrap_v4", BOOTSTRAP)
    r = RdapClient(db, min_interval=0)
    assert await r.registry_for("198.51.100.7") == "https://rdap.db.ripe.net/"
    assert await r.registry_for("198.51.7.7") == "https://rdap.arin.net/registry/"
    assert await r.registry_for("9.9.9.9") is None


def test_parse_network_registrant_and_abuse():
    p = parse_network(ARIN_8888)
    assert p["net_name"] == "GOGL" and p["registrant"] == "Google LLC"
    assert p["abuse_email"] == "network-abuse@google.com"
    assert p["net_range"] == "8.8.8.0 - 8.8.8.255" and p["net_type"] == "DIRECT ALLOCATION"


async def test_rdap_lookup_uses_bootstrap_and_handles_429(db: Database):
    db.kv_set("rdap_bootstrap_v4", BOOTSTRAP)
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        if len(calls) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        return httpx.Response(200, json=ARIN_8888)

    r = RdapClient(db, min_interval=0, transport=httpx.MockTransport(handler))
    out = await r.lookup("8.8.8.8")
    assert calls == ["https://rdap.arin.net/registry/ip/8.8.8.8"] * 2
    assert out["registrant"] == "Google LLC" and out["rdap_registry"] == "https://rdap.arin.net/registry/"
    assert (await r.lookup("10.0.0.1"))["net_name"] == "private/reserved"


def test_cymru_names_and_parsing():
    assert origin_name("216.90.108.31") == "31.108.90.216.origin.asn.cymru.com"
    assert origin_name("2001:db8::1").endswith(".origin6.asn.cymru.com")
    assert parse_origin("23028 | 216.90.108.0/24 | US | arin | 1998-09-25") == {
        "asn": 23028, "prefix": "216.90.108.0/24", "asn_registry": "arin"}
    assert parse_asname("23028 | US | arin | 2002-01-04 | TEAM-CYMRU, US") == "TEAM-CYMRU, US"


async def test_asn_lookup_resolves_name_once():
    answers = {"31.108.90.216.origin.asn.cymru.com": ["23028 | 216.90.108.0/24 | US | arin | 1998-09-25"],
               "AS23028.asn.cymru.com": ["23028 | US | arin | 2002-01-04 | TEAM-CYMRU, US"]}
    seen = []

    def resolve(name):
        seen.append(name)
        return answers.get(name, [])

    a = AsnLookup(resolve)
    out = await a.lookup("216.90.108.31")
    assert out == {"asn": 23028, "prefix": "216.90.108.0/24", "asn_registry": "arin", "as_name": "TEAM-CYMRU, US"}
    await a.lookup("216.90.108.31")
    assert seen.count("AS23028.asn.cymru.com") == 1
    assert await a.lookup("192.168.1.1") == {}


def test_ua_parse_and_drift():
    c1, c2, ip = parse_ua(UA_CHROME_1), parse_ua(UA_CHROME_2), parse_ua(UA_IPHONE)
    assert c1[0] == "Chrome" and c1[1] == "126" and c1[2] == "Windows"
    assert ua_change(c1, c1) is None
    assert ua_change(c1, c2) == "minor"
    assert ua_change(c2, c1) == "downgrade"          # Chrome 127 → 126: a spoofing signal, not an auto-update
    assert ua_change(ip, ("Mobile Safari", "17", "iOS", "15.0", "iPhone")) == "downgrade"
    assert ua_change(c1, ip) == "major"
    assert "Chrome 126 on Windows 10" in describe(c1)
    assert "iOS" in describe(ip) and "iPhone" in describe(ip)


async def test_ipqs_client_uses_www_host_and_maps_failure():
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        if "account" in req.url.path:
            return httpx.Response(200, json={"success": True, "credits": 4321})
        if req.url.path.endswith("/1.2.3.4"):
            return httpx.Response(200, json={"success": True, "fraud_score": 12, "connection_type": "Residential", "ISP": "X"})
        return httpx.Response(200, json={"success": False, "message": "Insufficient credits"})

    c = IPQSClient("KEY", transport=httpx.MockTransport(handler))
    body = await c.lookup("1.2.3.4", user_agent="UA", user_language="de")
    assert body["connection_type"] == "Residential"
    assert calls[0].url.host == "www.ipqualityscore.com" and "/api/json/ip/KEY/1.2.3.4" in calls[0].url.path
    assert calls[0].url.params["user_agent"] == "UA" and calls[0].url.params["strictness"] == "0"
    assert "python-httpx" not in calls[0].headers["user-agent"]
    with pytest.raises(IPQSError, match="Insufficient") as ei:
        await c.lookup("5.6.7.8")
    assert ei.value.charged is False          # no credit was spent: must not count against the day
    bad = IPQSClient("BAD", transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"success": False, "message": "Invalid IP address."})))
    with pytest.raises(IPQSError) as ei:
        await bad.lookup("5.6.7.8")
    assert ei.value.charged is True           # IPQS processed it: counts
    assert (await c.account())["credits"] == 4321
    assert await IPQSClient("").account() is None


async def test_enricher_caches_and_records_errors(db: Database):
    db.kv_set("rdap_bootstrap_v4", BOOTSTRAP)
    rdap = RdapClient(db, min_interval=0, transport=httpx.MockTransport(lambda r: httpx.Response(200, json=ARIN_8888)))
    asn = AsnLookup(lambda name: ["15169 | 8.8.8.0/24 | US | arin | 1992-12-01"] if "origin" in name else ["15169 | US | arin | 2000-03-30 | GOOGLE, US"])
    e = Enricher(db, Settings(enrich=True), rdap=rdap, asn=asn)
    n = await e.enrich_ips(["8.8.8.8", "8.8.8.8", "9.9.9.9"])
    assert n == 2
    rows = db.ip_rows(["8.8.8.8", "9.9.9.9"])
    assert rows["8.8.8.8"]["as_name"] == "GOOGLE, US" and rows["8.8.8.8"]["registrant"] == "Google LLC"
    assert rows["9.9.9.9"]["error"].startswith("rdap: no registry")
    assert await e.enrich_ips(["8.8.8.8"]) == 0
    assert db.ips_missing(["9.9.9.9"]) == []                       # errored just now: not yet retried
    assert db.ips_missing(["9.9.9.9"], retry_after_seconds=0) == ["9.9.9.9"]   # after the window: retried
    assert e.enrich_uas([UA_CHROME_1, UA_CHROME_1]) == 1
