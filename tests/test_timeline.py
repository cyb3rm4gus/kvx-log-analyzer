from loganalyzer.db import Database
from loganalyzer.enrich.ua import parse_ua
from loganalyzer.timeline import Filters, batch_flags, build_account_view, ipqs_context, url_path
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


def test_changes_section_and_batch_flags(db: Database):
    # chronological: Chrome126@IP-A(AS1) → Chrome127@IP-B(AS2) (upgrade + ASN change = both)
    # → Chrome126@IP-B (downgrade, no ASN change) → iPhone@IP-C (ASN unknown: not enriched)
    events = [
        ev("2026-08-01 10:00:00", ip="203.0.113.10", ua=UA_CHROME_1),
        ev("2026-08-02 10:00:00", ip="198.51.100.7", ua=UA_CHROME_2),
        ev("2026-08-03 10:00:00", ip="198.51.100.7", ua=UA_CHROME_1),
        ev("2026-08-04 10:00:00", ip="192.0.2.9", ua=UA_IPHONE),
    ]
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, list(reversed(events)), 1, has_more=False)
    db.save_ip("203.0.113.10", asn=64500, as_name="AS-A")
    db.save_ip("198.51.100.7", asn=64501, as_name="AS-B")
    # note: UAs deliberately NOT parsed beforehand — an existing batch must still work
    v = build_account_view(db, U1)
    kinds = [(c.created_at[:10], c.ua_change, c.asn_changed, c.both) for c in v["changes"]]
    assert kinds == [("2026-08-02", "minor", True, True), ("2026-08-03", "downgrade", False, False),
                     ("2026-08-04", "major", None, False)]
    both = v["changes"][0]
    assert both.prev_ua == UA_CHROME_1 and both.ua == UA_CHROME_2       # full strings, not descriptions
    assert both.prev_path == "/lobby" and both.prev_time == "2026-08-01 10:00:00" and both.prev_session_short == "sess-aaa"
    assert (both.prev_asn, both.asn) == (64500, 64501) and both.as_name == "AS-B"
    assert v["change_counts"] == {"ua_upgrade": 1, "ua_downgrade": 1, "ua_major": 1, "asn": 1, "asn_unknown": 1, "both": 1, "total": 3}
    assert len(db.ua_rows([UA_CHROME_1, UA_CHROME_2, UA_IPHONE])) == 3  # parsed and saved on the way
    assert v["change_years"] == ["2026"] and v["change_counts"]["total"] == 3
    # year filter applies to the Changes section only
    db.insert_events_page("b1", U1, [ev("2025-12-31 23:00:00", ip="192.0.2.9", ua=UA_CHROME_1,
                                        url="https://platform.example/old", referrer="https://ads.example/x")], 2, has_more=False)
    # the 2025 event is now the earliest: it has no predecessor, so it is not itself a change —
    # the change it causes (IP → ASN unknown) lands on the first 2026 row
    v = build_account_view(db, U1, Filters(changes_year="2025"))
    assert v["change_years"] == ["2026"] and v["events"] == 5
    assert v["changes"] == [] and v["change_counts"]["total"] == 4
    v = build_account_view(db, U1, Filters(changes_year="2026"))
    assert all(c.day[:4] == "2026" for c in v["changes"]) and len(v["changes"]) == 4
    first = v["changes"][0]           # 2026-08-01: came from the 2025 event on /old, referred from ads
    assert first.prev_path == "/old" and first.prev_referrer == "https://ads.example/x"
    flags = batch_flags(db, [U1, "00000000-0000-4000-8000-000000000000"])
    assert flags[U1] == {"ua_downgrade": 1, "ua_other": 2, "asn": 1, "both": 1}
    assert flags["00000000-0000-4000-8000-000000000000"] == {"ua_downgrade": 0, "ua_other": 0, "asn": 0, "both": 0}


def test_change_kind_filters_and_major_threshold(db: Database):
    from loganalyzer.timeline import change_matches, row_kinds
    chrome = lambda major: f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36"  # noqa: E731
    events = [ev("2026-01-01 00:00:00", ip="203.0.113.10", ua=chrome(150)),
              ev("2026-01-02 00:00:00", ip="203.0.113.10", ua=chrome(144)),   # −6: downgrade, no ASN change
              ev("2026-01-03 00:00:00", ip="198.51.100.7", ua=chrome(145)),   # +1 upgrade + ASN change
              ev("2026-01-04 00:00:00", ip="198.51.100.7", ua=chrome(144))]   # −1 downgrade
    db.create_batch("b1", [U1]); db.insert_events_page("b1", U1, list(reversed(events)), 1, has_more=False)
    db.save_ip("203.0.113.10", asn=1, as_name="A"); db.save_ip("198.51.100.7", asn=2, as_name="B")
    v = build_account_view(db, U1)
    deltas = [(c.day, c.ua_change, c.ua_delta, c.asn_changed) for c in v["changes"]]
    assert deltas == [("2026-01-02", "downgrade", -6, False), ("2026-01-03", "minor", 1, True), ("2026-01-04", "downgrade", -1, False)]
    # threshold 3: the −6 downgrade counts, the −1 does not; the +1 upgrade row survives only via its ASN change
    v = build_account_view(db, U1, Filters(min_delta=3))
    assert [(c.day, sorted(row_kinds(c, 3))) for c in v["changes"]] == [("2026-01-02", ["downgrade"]), ("2026-01-03", ["asn"])]
    # only downgrades ≥ 3 majors
    v = build_account_view(db, U1, Filters(kinds=frozenset({"downgrade"}), min_delta=3))
    assert [c.day for c in v["changes"]] == ["2026-01-02"]
    # downgrade + ASN change on the same event: none here; any-of: three rows
    assert build_account_view(db, U1, Filters(kinds=frozenset({"downgrade", "asn"}), combine=True))["changes"] == []
    assert len(build_account_view(db, U1, Filters(kinds=frozenset({"downgrade", "asn"})))["changes"]) == 3
    # upgrade + ASN on the same event: the 01-03 row
    v = build_account_view(db, U1, Filters(kinds=frozenset({"upgrade", "asn"}), combine=True))
    assert [c.day for c in v["changes"]] == ["2026-01-03"]
    assert v["change_counts"]["both"] == 1 and v["change_counts"]["total"] == 3
    # nothing checked → nothing shown; query-string round trip keeps every choice
    assert build_account_view(db, U1, Filters(kinds=frozenset()))["changes"] == []
    f = Filters(ip="1.2.3.4", changes_year="2026", kinds=frozenset({"downgrade", "asn"}), combine=True, min_delta=3)
    assert f.timeline_qs() == "ip=1.2.3.4&kf=1&k=downgrade&k=asn&combine=1&delta=3"
    assert f.timeline_qs(exclude=("kf", "k", "combine", "delta")) == "ip=1.2.3.4&cy=2026"
    assert change_matches(v["changes"][0], Filters(kinds=frozenset({"asn"})))


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
