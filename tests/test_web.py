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
        if not client.get(f"/batches/{batch_id}/status").json().get("live"):
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
    assert "bg-orange-lt" in page and page.count("bg-green-lt") >= 2   # unknown + done, native Tabler badges
    status = client.get(f"/batches/{batch_id}/status").json()
    assert status["phase"] in ("done", "enriching") and not status["live"]
    assert {u["status"] for u in status["uuids"]} == {"done", "unknown"}
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
    # golden pin of the timeline table (fetched-at stamps stripped: they are wall-clock)
    table = re.search(r'<table class="table table-sm card-table table-vcenter small timeline">.*?</table>', html, re.S).group(0)
    table = re.sub(r"fetched \d{4}-\d{2}-\d{2} \d{2}:\d{2}", "fetched <t>", table)
    if os.environ.get("UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(table)
    assert GOLDEN.exists(), "golden fixture missing — regenerate deliberately with UPDATE_GOLDEN=1"
    assert table == GOLDEN.read_text()
    assert table.count("session <a") == 3
    # filters
    assert "1 of 4 events" in client.get(f"/accounts/{U1}?path=deposit").text
    assert client.get(f"/accounts/{U2}").status_code == 200   # no events: informative, not an error
    assert client.get("/accounts/not-a-uuid").status_code == 404


def test_status_endpoint_shows_done_uuids_during_enrichment(app, client, db):
    # the reported bug: table frozen on "fetching" while the log counts thousands of IPs.
    # With uuids terminal but a job still in the enriching phase, /status must report them done.
    from loganalyzer.jobs import BatchJob
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)  # 2 distinct IPs
    db.save_ip("203.0.113.10", net_name="X", asn=1)                                       # 1 enriched
    job = BatchJob("b1"); job.phase = "enriching"; job.emit("enrichment: 1 of 2 IPs")
    app.state.runner.jobs["b1"] = job
    s = client.get("/batches/b1/status").json()
    assert s["live"] and s["phase"] == "enriching"
    assert s["uuids"][0]["status"] == "done" and s["uuids"][0]["ips"] == 2
    assert s["enrich"] == {"done": 1, "total": 2}
    assert s["log"] == ["enrichment: 1 of 2 IPs"]


def test_changes_section_and_batch_downgrade_flag(client, db):
    from tests.conftest import UA_CHROME_1, UA_CHROME_2
    events = [ev("2026-08-01 10:00:00", ip="203.0.113.10", ua=UA_CHROME_2),
              ev("2026-08-02 10:00:00", ip="198.51.100.7", ua=UA_CHROME_1)]   # 127 → 126 + new IP
    db.create_batch("b1", [U1]); db.set_batch_status("b1", "done")
    db.insert_events_page("b1", U1, list(reversed(events)), 1, has_more=False)
    db.save_ip("203.0.113.10", asn=1, as_name="ONE"); db.save_ip("198.51.100.7", asn=2, as_name="TWO")
    page = client.get(f"/accounts/{U1}").text
    assert "Changes — 1 event(s)" in page and "UA downgrade" in page and "ASN change" in page
    assert page.count(UA_CHROME_2) >= 2 and page.count(UA_CHROME_1) >= 2      # full UA lines, before and after
    assert "AS1 ONE" in page and "AS2 TWO" in page and 'badge bg-purple-lt">both' in page
    assert "on page" in page and "went to" in page and "/lobby" in page      # before/after with pages
    # year filter: 2026 keeps it, 2024 hides it, timeline filters are preserved in the year links
    assert "Changes — 1 event(s)" in client.get(f"/accounts/{U1}?cy=2026").text
    assert "No matching changes in 2024 (1 in total" in client.get(f"/accounts/{U1}?cy=2024").text
    # kind checkboxes: only-ASN hides nothing here (row has both), only-upgrade hides it, combine needs both kinds
    assert "Changes — 1 event(s)" in client.get(f"/accounts/{U1}?kf=1&k=asn").text
    assert "No matching changes" in client.get(f"/accounts/{U1}?kf=1&k=upgrade").text
    assert "Changes — 1 event(s)" in client.get(f"/accounts/{U1}?kf=1&k=downgrade&k=asn&combine=1").text
    assert "No matching changes" in client.get(f"/accounts/{U1}?kf=1&k=downgrade&k=major&combine=1").text
    # threshold: 127→126 is a 1-major jump; delta=3 hides the downgrade but the ASN change still shows
    page = client.get(f"/accounts/{U1}?kf=1&k=downgrade&delta=3").text
    assert "No matching changes" in page
    page = client.get(f"/accounts/{U1}?delta=3").text        # row stays (ASN change) — Kind column drops the sub-threshold downgrade
    assert "Changes — 1 event(s)" in page and 'bg-yellow-lt">ASN change</span>' in page
    assert 'bg-red-lt">UA downgrade</span>' not in page and "downgrade -1 major" in page   # fact kept on the After side
    assert "-1 major" in client.get(f"/accounts/{U1}").text
    # the form keeps its state and the year links keep the kind choices
    page = client.get(f"/accounts/{U1}?kf=1&k=downgrade&combine=1&delta=3&cy=2026").text
    assert 'value="downgrade" checked' in page and 'name="combine" value="1" checked' in page and 'value="3"' in page
    assert 'name="cy" value="2026"' in page                                     # the kind form keeps the year
    assert "kf=1&amp;k=downgrade&amp;combine=1&amp;delta=3#changes" in page     # the "all years" button keeps the kinds
    assert "cy=2026#changes" in client.get(f"/accounts/{U1}?cy=2024&ip=198.51.100.7").text
    batch = client.get("/batches/b1").text
    assert "UA downgrade 1" in batch and "UA+ASN 1" in batch
    status = client.get("/batches/b1/status").json()
    assert status["uuids"][0]["flags"] == {"ua_downgrade": 1, "ua_other": 0, "asn": 1, "both": 1, "ua_jump": 0}
    assert "UA jump ≥2 " not in batch.split("<tbody")[1].split("</tbody>")[0]   # legend mentions it; no row badge
    # a 3-major downgrade on another account gets the badge
    db.insert_events_page("b1", U2, list(reversed([ev("2026-08-01 10:00:00", ua=UA_CHROME_2.replace("127", "130")),
                                                    ev("2026-08-02 10:00:00", ua=UA_CHROME_1)])), 1, has_more=False)
    db.execute("INSERT INTO batch_uuids (batch_id, uuid, status) VALUES ('b1', ?, 'done')", (U2,))
    assert "UA jump ≥2 1" in client.get("/batches/b1").text


def test_native_tabler_badges_only(client, db):
    db.create_batch("b1", [U1]); db.set_batch_status("b1", "done")
    db.set_uuid_status("b1", U1, "done")
    page = client.get("/batches/b1").text
    assert "bg-green-lt" in page and 'class="badge status-' not in page   # no custom status-* classes


def test_multi_page_account_has_no_caveat(client, db):
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=True)
    db.insert_events_page("b1", U1, [], 2, has_more=False)
    page = client.get(f"/accounts/{U1}").text
    assert "caveat" not in page.lower() and page.count("session <a") == 3


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
