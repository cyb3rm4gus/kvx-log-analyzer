import os
import re
import time
from pathlib import Path

import httpx

from loganalyzer.enrich.ipqs import IPQSClient
from loganalyzer.enrich.ua import parse_ua
from tests.conftest import U1, U2, U_UNKNOWN, ev, sample_events

GOLDEN = Path(__file__).parent / "fixtures" / "account_timeline.html"


def wait_batch(client, batch_id: str, timeout: float = 5.0) -> None:
    for _ in range(int(timeout / 0.05)):
        r = client.get(f"/batches/{batch_id}")
        if 'status-running">running' not in r.text and 'live' not in r.text:
            return
        time.sleep(0.05)
    raise AssertionError("batch did not finish")


def test_home_and_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "Process uuids" in r.text
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert client.get("/healthz").json() == {"status": "ok"}


def test_host_guard(client):
    assert client.get("/", headers={"host": "evil.example"}).status_code == 400
    assert client.get("/", headers={"host": "testserver"}).status_code == 400
    assert client.get("/", headers={"host": "localhost:8090"}).status_code == 200


def test_paste_creates_batch_and_runs(client, db):
    r = client.post("/batches", data={"uuids": f"{U1}\n{U2}\n{U_UNKNOWN}\nnonsense"}, follow_redirects=False)
    assert r.status_code == 303
    batch_id = r.headers["location"].split("/")[2].split("?")[0]
    assert "rejected=1" in r.headers["location"]
    wait_batch(client, batch_id)
    page = client.get(f"/batches/{batch_id}").text
    assert 'status-unknown' in page and page.count('status-done') >= 2
    assert client.get(f"/batches/{batch_id}/events").text.strip().endswith("event: end\ndata: {}")
    assert batch_id in client.get("/").text


def test_empty_paste_shows_error(client):
    r = client.post("/batches", data={"uuids": "abc"})
    assert r.status_code == 200 and "No valid uuids" in r.text


def test_account_page_and_golden_timeline(client, db):
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)
    for ua in {e["user_agent"] for e in sample_events()}:
        db.save_ua(ua, *parse_ua(ua))
    db.save_ip("198.51.100.7", net_name="TEST-NET-2", registrant="Example Ltd", net_country="TR", asn=64500, as_name="EXAMPLE-AS")
    db.save_ipqs("198.51.100.7", {"success": True, "fraud_score": 88.0, "connection_type": "Data Center",
                                  "ISP": "Hoster", "proxy": True, "vpn": True})
    html = client.get(f"/accounts/{U1}").text
    assert "IP changed" in html and "UA changed" in html and "UA version" in html
    assert "EXAMPLE-AS" in html and "Data Center" in html and "score 88.0" in html
    assert "IPQS_KEY not set" in html
    assert "Page-boundary caveat" not in html
    # golden pin of the timeline table (fetched-at stamps stripped: they are wall-clock)
    table = re.search(r'<table class="table table-sm card-table table-vcenter small timeline">.*?</table>', html, re.S).group(0)
    table = re.sub(r"fetched \d{4}-\d{2}-\d{2} \d{2}:\d{2}", "fetched <t>", table)
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(table)
    assert GOLDEN.exists(), "golden fixture missing — regenerate deliberately with UPDATE_GOLDEN=1"
    assert table == GOLDEN.read_text()
    assert "session-row" in table and table.count("session <a") == 3
    # filters
    assert "1 of 4 events" in client.get(f"/accounts/{U1}?path=deposit").text
    assert client.get(f"/accounts/{U2}").status_code == 200   # no events: informative, not an error
    assert client.get("/accounts/not-a-uuid").status_code == 404


def test_caveat_shown_for_multi_page_account(client, db):
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=True)
    db.insert_events_page("b1", U1, [], 2, has_more=False)
    assert "Page-boundary caveat" in client.get(f"/accounts/{U1}").text


def test_ipqs_button_respects_daily_cap(app, client, db, settings):
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        if "account" in req.url.path:
            return httpx.Response(200, json={"success": True, "credits": 100})
        return httpx.Response(200, json={"success": True, "fraud_score": 5, "connection_type": "Mobile", "ISP": "Carrier"})

    app.state.ipqs = IPQSClient("KEY", transport=httpx.MockTransport(handler))
    app.state.settings = settings.__class__(**{**settings.__dict__, "ipqs_key": "KEY", "ipqs_daily_cap": 1})
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)
    page = client.get(f"/accounts/{U1}").text
    assert "1 of 1 left today" in page and "IPQS this account (1 lookups now, 1 tomorrow)" in page
    r = client.post(f"/accounts/{U1}/ipqs", data={"force": "0"}, follow_redirects=False)
    assert r.status_code == 303
    for _ in range(50):
        run = app.state.ipqs_runs.get(U1)
        if run and run.finished:
            break
        time.sleep(0.05)
    assert run.finished and run.total == 2 and run.done == 1 and run.capped == 1
    assert db.ipqs_spent_today() == 1
    assert len(db.ipqs_rows(["203.0.113.10", "198.51.100.7"])) == 1
    page = client.get(f"/accounts/{U1}").text
    assert "0 of 1 left today" in page and "Mobile" in page and "IPQS this account (0 lookups" in page
    assert "daily cap reached" in page and "1 IP(s) wait for tomorrow" in page
    assert "100 credits" in page   # filled by the press, not by the render


def wait_runs(app, *uuids, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        runs = [app.state.ipqs_runs.get(u) for u in uuids]
        if all(r and r.finished for r in runs):
            return runs
        time.sleep(0.05)
    raise AssertionError("ipqs runs did not finish")


def test_ipqs_cap_holds_across_concurrent_accounts(app, client, db, settings):
    import asyncio

    async def slow(req: httpx.Request) -> httpx.Response:
        await asyncio.sleep(0.2)
        if "account" in req.url.path:
            return httpx.Response(200, json={"success": True, "credits": 9})
        return httpx.Response(200, json={"success": True, "fraud_score": 1, "connection_type": "Mobile"})

    app.state.ipqs = IPQSClient("KEY", transport=httpx.MockTransport(slow))
    app.state.settings = settings.__class__(**{**settings.__dict__, "ipqs_key": "KEY", "ipqs_daily_cap": 2})
    db.create_batch("b1", [U1, U2])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)       # 2 IPs
    db.insert_events_page("b1", U2, [ev("2026-07-01 00:00:00", ip="192.0.2.9"), ev("2026-07-02 00:00:00", ip="192.0.2.8")], 1, has_more=False)
    client.post(f"/accounts/{U1}/ipqs", data={"force": "0"}, follow_redirects=False)
    client.post(f"/accounts/{U2}/ipqs", data={"force": "0"}, follow_redirects=False)
    r1, r2 = wait_runs(app, U1, U2)
    assert db.ipqs_spent_today() == 2                        # never past the cap
    assert r1.done + r2.done == 2 and r1.capped + r2.capped == 2
    assert any("daily cap" in e for e in r1.errors + r2.errors)


def test_ipqs_failure_is_persisted_and_uncharged_transport_errors_do_not_count(app, client, db, settings):
    def handler(req: httpx.Request) -> httpx.Response:
        if "account" in req.url.path:
            return httpx.Response(200, json={"success": True, "credits": 9})
        if req.url.path.endswith("203.0.113.10"):
            return httpx.Response(200, json={"success": False, "message": "Invalid IP address."})
        raise httpx.ConnectError("down")

    app.state.ipqs = IPQSClient("KEY", transport=httpx.MockTransport(handler))
    app.state.settings = settings.__class__(**{**settings.__dict__, "ipqs_key": "KEY", "ipqs_daily_cap": 10})
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)
    client.post(f"/accounts/{U1}/ipqs", data={"force": "0"}, follow_redirects=False)
    (run,) = wait_runs(app, U1)
    assert run.failed == 2
    assert db.ipqs_spent_today() == 1                        # the processed one, not the transport failure
    app.state.ipqs_runs.clear()                              # simulate a restart: the page must still say so
    page = client.get(f"/accounts/{U1}").text
    assert "lookup failed: Invalid IP address." in page and "lookup failed: transport: ConnectError" in page
    assert "not looked up" not in page


def test_null_fraud_score_renders(client, db):
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)
    db.save_ipqs("198.51.100.7", {"success": True, "connection_type": "Residential", "ISP": "X"})
    r = client.get(f"/accounts/{U1}")
    assert r.status_code == 200 and "no score" in r.text


def test_retry_failed_uuids(client, db, mock_gh):
    db.create_batch("b1", [U1])
    db.set_batch_status("b1", "done")
    db.set_uuid_status("b1", U1, "failed", error="gave up")
    page = client.get("/batches/b1").text
    assert "Retry 1 failed uuid(s)" in page and "<th class=\"text-end\">IPs</th>" in page
    r = client.post("/batches/b1/retry", follow_redirects=False)
    assert r.status_code == 303
    wait_batch(client, "b1")
    assert {x["status"] for x in db.batch_uuids("b1")} == {"done"}
    assert len(db.events_for(U1)) == 4


def test_purge_from_ui(client, db):
    db.create_batch("b1", [U1])
    db.set_batch_status("b1", "done")
    r = client.post("/batches/b1/purge", follow_redirects=False)
    assert r.status_code == 303 and client.get("/batches/b1").status_code == 404
