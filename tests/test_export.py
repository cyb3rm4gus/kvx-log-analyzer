import io
import json
import sqlite3
import tarfile

from loganalyzer.db import EVENT_COLUMNS, Database
from loganalyzer.export import build_export, safe_name
from tests.conftest import PII_EMAIL, U1, U2, ev, sample_events


def test_safe_name():
    assert safe_name("case 2026/09: A&B", "fallback") == "case_2026_09_A_B"
    assert safe_name("  ..weird..  ", "fallback") == "weird"
    assert safe_name("", "20260911-1200-ab") == "20260911-1200-ab"
    assert safe_name(None, "x") == "x"


def test_export_one_json_per_uuid_as_guardhouse_sends_them(db: Database):
    db.create_batch("b1", [U1, U2])
    db.insert_events_page("b1", U1, list(reversed(sample_events())), 1, has_more=False)
    db.insert_events_page("b1", U2, [], 1, has_more=False)          # a uuid with no events → empty array
    db.set_batch_alias("b1", "Case 42/A")
    name, data = build_export(db, "b1")
    assert name == "export_Case_42_A.tar.gz"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = {m.name: tar.extractfile(m).read().decode() for m in tar.getmembers()}
    assert set(members) == {f"export_Case_42_A_{U1}.json", f"export_Case_42_A_{U2}.json"}
    events = json.loads(members[f"export_Case_42_A_{U1}.json"])
    assert isinstance(events, list) and len(events) == 4
    assert all(list(e.keys()) == list(EVENT_COLUMNS) for e in events)     # the nine fields, Guardhouse's order, nothing else
    assert [e["created_at"] for e in events] == sorted((e["created_at"] for e in events), reverse=True)  # newest first
    assert events[-1] == {**{c: sample_events()[0][c] for c in EVENT_COLUMNS}}
    assert json.loads(members[f"export_Case_42_A_{U2}.json"]) == []
    assert PII_EMAIL not in data.decode("latin1") and "player_uuid" not in members[f"export_Case_42_A_{U1}.json"]


def test_export_without_alias_falls_back_to_batch_id(db: Database):
    db.create_batch("b1", [U1])
    db.insert_events_page("b1", U1, [ev("2026-01-01 00:00:00")], 1, has_more=False)
    name, data = build_export(db, "b1")
    assert name == "export_b1.tar.gz"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        assert [m.name for m in tar.getmembers()] == [f"export_b1_{U1}.json"]


def test_alias_column_is_added_to_an_existing_store(tmp_path):
    path = str(tmp_path / "old.sqlite")
    raw = sqlite3.connect(path)
    raw.executescript("""CREATE TABLE batches (id TEXT PRIMARY KEY, created_at TEXT NOT NULL, status TEXT NOT NULL,
                                              uuid_count INTEGER NOT NULL, error TEXT);
                         INSERT INTO batches VALUES ('old', '2026-09-01 00:00:00', 'done', 0, NULL);""")
    raw.commit(); raw.close()
    db = Database(path)                       # opens the pre-alias store
    db.set_batch_alias("old", "legacy")
    assert db.one("SELECT alias FROM batches WHERE id = 'old'")["alias"] == "legacy"
