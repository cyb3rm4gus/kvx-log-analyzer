import asyncio

import httpx

from loganalyzer.db import Database
from loganalyzer.jobs import JobRunner
from tests.conftest import PII_EMAIL, PII_PHONE, U1, U2, U_UNKNOWN, MockGuardhouse, ev, paged, sample_events


async def run(runner: JobRunner, batch: str, uuids: list[str]) -> None:
    runner.db.create_batch(batch, uuids)
    job = runner.start(batch)
    await asyncio.wait_for(job.task, 10)
    assert job.done


def statuses(db: Database, batch: str) -> dict[str, str]:
    return {r["uuid"]: r["status"] for r in db.batch_uuids(batch)}


async def test_batch_pulls_all_pages_and_marks_unknown(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    mock_gh.pages[U1] = paged(sample_events(), 2)   # two pages
    await run(runner, "b1", [U1, U2, U_UNKNOWN])
    st = statuses(db, "b1")
    assert st == {U1: "done", U2: "done", U_UNKNOWN: "unknown"}
    assert len(db.events_for(U1)) == 4
    assert [c for c in mock_gh.calls if c[0] == U1] == [(U1, 1), (U1, 2)]
    row = db.one("SELECT pages_done, has_more FROM batch_uuids WHERE uuid = ?", (U1,))
    assert (row["pages_done"], row["has_more"]) == (2, 0)
    assert db.one("SELECT status FROM batches WHERE id = 'b1'")["status"] == "done"


async def test_no_pii_reaches_the_store(runner: JobRunner, db: Database):
    await run(runner, "b1", [U1])
    dump = "\n".join(db._conn.iterdump())
    assert PII_EMAIL not in dump and PII_PHONE not in dump


async def test_duplicate_across_page_boundary_collapses_exact_repeat(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    e = ev("2026-08-01 10:00:00")
    other = ev("2026-08-01 10:00:00", url="https://platform.example/other")
    # page 1 ends with `e`, page 2 starts with `e` again (H3-style duplicate); `other` distinct same-second row
    mock_gh.pages[U1] = [[other, e], [e, ev("2026-07-31 09:00:00")]]
    await run(runner, "b1", [U1])
    assert len(db.events_for(U1)) == 3
    assert db.one("SELECT pages_done FROM batch_uuids WHERE uuid = ?", (U1,))["pages_done"] == 2


async def test_pause_and_resume_when_guardhouse_unreachable(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    mock_gh.pages[U1] = paged(sample_events(), 2)
    seen = {"n": 0}
    original = mock_gh.handler

    def flaky(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/query":
            seen["n"] += 1
            if seen["n"] == 2:            # the second page: connection drops
                raise httpx.ConnectError("vpn down")
        return original(request)

    runner.client._transport = httpx.MockTransport(flaky)
    await run(runner, "b1", [U1])
    assert statuses(db, "b1") == {U1: "done"}
    assert len(db.events_for(U1)) == 4
    assert any("paused" in p.message for p in runner.jobs["b1"].events)
    assert any("resuming at page 2" in p.message for p in runner.jobs["b1"].events)


async def test_gives_up_when_guardhouse_stays_down(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    mock_gh.raise_connect = True
    await run(runner, "b1", [U1])
    assert statuses(db, "b1") == {U1: "failed"}


async def test_429_then_success(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    import time
    mock_gh.script(U1, httpx.Response(429, headers={"Retry-After": "0"},
                                      json={"error": {"code": "rate_limited", "message": "slow", "request_id": "x"}}))
    t = time.monotonic()
    await run(runner, "b1", [U1])
    assert time.monotonic() - t < 1.0          # Retry-After: 0 means 0, not the 5 s default
    assert statuses(db, "b1") == {U1: "done"}
    assert len(db.events_for(U1)) == 4


async def test_endless_429_fails_the_uuid_loudly(runner: JobRunner, db: Database, mock_gh: MockGuardhouse, monkeypatch):
    monkeypatch.setattr("loganalyzer.jobs.UNAVAILABLE_MAX_WAIT", 0.05)
    for _ in range(50):
        mock_gh.script(U1, httpx.Response(503, headers={"Retry-After": "0.01"},
                                          json={"error": {"code": "overloaded", "message": "m", "request_id": "x"}}))
    await run(runner, "b1", [U1])
    assert statuses(db, "b1") == {U1: "failed"}
    assert "kept answering 503" in db.one("SELECT error FROM batch_uuids")["error"]


async def test_read_timeout_is_upstream_not_vpn(runner: JobRunner, db: Database, mock_gh: MockGuardhouse, monkeypatch):
    monkeypatch.setattr("loganalyzer.jobs.UPSTREAM_BACKOFF", (0.0, 0.0, 0.0))

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("page took too long")

    runner.client._transport = httpx.MockTransport(slow)
    await run(runner, "b1", [U1])
    assert statuses(db, "b1") == {U1: "failed"}
    assert "timed out" in db.one("SELECT error FROM batch_uuids")["error"]
    assert not any("paused" in p.message for p in runner.jobs["b1"].events)


async def test_oversized_page_is_abandoned(runner: JobRunner, db: Database, mock_gh: MockGuardhouse, monkeypatch):
    monkeypatch.setattr("loganalyzer.guardhouse.MAX_PAGE_BYTES", 500)
    monkeypatch.setattr("loganalyzer.jobs.UPSTREAM_BACKOFF", (0.0, 0.0, 0.0))
    await run(runner, "b1", [U1])
    assert statuses(db, "b1") == {U1: "failed"}
    assert "exceeds" in db.one("SELECT error FROM batch_uuids")["error"]


async def test_empty_page_claiming_more_does_not_loop(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    mock_gh.script(U1, httpx.Response(200, json={"player": {}, "events": [], "page": 1, "has_more": True}))
    await run(runner, "b1", [U1])
    assert statuses(db, "b1") == {U1: "done"} and len(mock_gh.calls) == 1


async def test_retry_after_http_date(mock_gh: MockGuardhouse):
    from email.utils import format_datetime
    from datetime import UTC, datetime, timedelta
    from loganalyzer import guardhouse as gh
    when = format_datetime(datetime.now(UTC) + timedelta(seconds=30), usegmt=True)
    mock_gh.script(U1, httpx.Response(429, headers={"Retry-After": when},
                                      json={"error": {"code": "rate_limited", "message": "m", "request_id": "x"}}))
    import pytest
    with pytest.raises(gh.Unavailable) as ei:
        await gh.GuardhouseClient("http://gh.test", "t", transport=mock_gh.transport()).events_page(U1)
    assert 25 <= ei.value.retry_after <= 30


async def test_upstream_errors_fail_only_that_uuid(runner: JobRunner, db: Database, mock_gh: MockGuardhouse, monkeypatch):
    monkeypatch.setattr("loganalyzer.jobs.UPSTREAM_BACKOFF", (0.0, 0.0, 0.0))
    for _ in range(4):
        mock_gh.script(U1, httpx.Response(502, json={"error": {"code": "upstream_failed", "message": "ch", "request_id": "x"}}))
    await run(runner, "b1", [U1, U2])
    assert statuses(db, "b1") == {U1: "failed", U2: "done"}


async def test_auth_error_stops_the_batch(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    runner.settings = runner.settings.__class__(**{**runner.settings.__dict__, "gh_concurrency": 1})
    mock_gh.script(U1, httpx.Response(401, json={"error": {"code": "unauthenticated", "message": "bad", "request_id": "x"}}))
    await run(runner, "b1", [U1, U2])
    assert db.one("SELECT status FROM batches WHERE id = 'b1'")["status"] == "failed"
    assert statuses(db, "b1")[U2] == "failed"


async def test_desync_and_empty(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    mock_gh.script(U1, httpx.Response(500, json={"error": {"code": "source_desync", "message": "d", "request_id": "x"}}))
    mock_gh.pages[U2] = [[]]
    await run(runner, "b1", [U1, U2])
    assert statuses(db, "b1") == {U1: "no_events", U2: "no_events"}


async def test_resume_skips_finished_uuids(runner: JobRunner, db: Database, mock_gh: MockGuardhouse):
    await run(runner, "b1", [U1])
    calls = len(mock_gh.calls)
    job = runner.start("b1")   # already done: nothing to do
    await asyncio.wait_for(job.task, 5)
    assert len(mock_gh.calls) == calls


async def test_purge_batch_removes_orphaned_events_only(runner: JobRunner, db: Database):
    await run(runner, "b1", [U1, U2])
    await run(runner, "b2", [U2])
    deleted = db.purge_batch("b1")
    assert deleted == 4                       # U1's events; U2 still referenced by b2
    assert db.events_for(U1) == [] and len(db.events_for(U2)) == 1
    assert db.one("SELECT COUNT(*) FROM batches")[0] == 1
