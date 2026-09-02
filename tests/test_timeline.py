from loganalyzer.db import Database
from loganalyzer.enrich.ua import parse_ua
from loganalyzer.timeline import Filters, build_account_view, ipqs_context, url_path
from tests.conftest import U1, UA_CHROME_1, UA_CHROME_2, UA_IPHONE, ev, sample_events


def load(db: Database, events=None, pages: int = 1) -> None:
    events = events or sample_events()
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(events)), 1, has_more=pages > 1)
    if pages > 1:
        db.insert_events_page("b1", U1, [], pages, has_more=False)
    for ua in {e["user_agent"] for e in events}:
        db.save_ua(ua, *parse_ua(ua))


def test_markers_are_chronological_and_view_is_newest_first(db: Database):
    load(db)
    v = build_account_view(db, U1)
    assert v["events"] == 4 and v["sessions"] == 3
    assert v["first_seen"] == "2026-08-01 10:00:00" and v["last_seen"] == "2026-08-03 21:30:00"
    rows = [r for _, groups in v["days"] for _, rs in groups for r in rs]
    assert [r.created_at for r in rows] == sorted((r.created_at for r in rows), reverse=True)
    assert [(day, [s for s, _ in groups]) for day, groups in v["days"]] == [
        ("2026-08-03", ["sess-cccc-3"]), ("2026-08-02", ["sess-bbbb-2"]), ("2026-08-01", ["sess-aaaa-1"])]
    by_time = {r.created_at: r for r in rows}
    assert by_time["2026-08-01 10:00:00"].ip_changed is False
    r2 = by_time["2026-08-02 09:00:00"]
    assert r2.ip_changed and r2.prev_ip == "203.0.113.10" and r2.ua_change == "minor"
    r3 = by_time["2026-08-03 21:30:00"]
    assert r3.ip_changed is False and r3.ua_change == "major" and "Chrome" in r3.prev_ua_desc
    assert v["ip_changes"] == 1 and v["ua_changes"] == 2
    assert v["countries"][0] == ("DE", 3)
    assert v["pages"] == 1


def test_pages_reported_without_caveat(db: Database):
    # Guardhouse's H3 (page-boundary drops) was fixed 2026-09-02 (unique `id` tiebreaker); the
    # view reports the page count and no longer carries a caveat flag.
    load(db, pages=2)
    v = build_account_view(db, U1)
    assert v["pages"] == 2 and "caveat" not in v


def test_filters_keep_change_context(db: Database):
    load(db)
    v = build_account_view(db, U1, Filters(ip="198.51.100.7"))
    assert v["shown"] == 2 and v["events"] == 4
    rows = [r for _, groups in v["days"] for _, rs in groups for r in rs]
    assert any(r.ip_changed for r in rows)   # computed against the unfiltered history
    v = build_account_view(db, U1, Filters(path="deposit"))
    assert v["shown"] == 1
    v = build_account_view(db, U1, Filters(date_from="2026-08-02", date_to="2026-08-02"))
    assert v["shown"] == 1
    v = build_account_view(db, U1, Filters(session="sess-aaaa-1"))
    assert v["shown"] == 2


def test_url_path():
    assert url_path("https://platform.example/deposit?amt=10") == "/deposit?amt=10"
    assert url_path("https://platform.example") == "/"
    assert url_path("/relative/path") == "/relative/path"
    assert url_path("") == ""


def test_ipqs_context_is_most_used_ua_and_language(db: Database):
    load(db)
    ua, lang = ipqs_context(db, U1, "198.51.100.7")
    assert ua in (UA_CHROME_2, UA_IPHONE) and lang in ("de", "tr")
    load2 = [ev("2026-08-05 00:00:00", ip="1.1.1.1", ua=UA_CHROME_1, language="en")] * 1
    db.insert_events_page("b1", U1, load2, 3, has_more=False)
    assert ipqs_context(db, U1, "1.1.1.1") == (UA_CHROME_1, "en")
