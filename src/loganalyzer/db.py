"""SQLite store: stdlib `sqlite3`, one connection, one lock (single-process local tool)."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = Path(__file__).parent / "schema.sql"

EVENT_COLUMNS = (
    "frontend_session_uuid", "country", "language", "user_agent", "click_id",
    "url", "referrer_url", "ip_address", "created_at",
)
PII_KEYS = frozenset({"email", "phone"})


def now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


class Database:
    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA.read_text())

    # -- primitives -------------------------------------------------------
    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._conn.execute(sql, tuple(params))

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        with self._lock:
            self._conn.executemany(sql, [tuple(r) for r in rows])

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        return self.execute(sql, params).fetchall()

    def one(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        return self.execute(sql, params).fetchone()

    def transaction(self) -> threading.RLock:
        return self._lock

    # -- batches ------------------------------------------------------------
    def create_batch(self, batch_id: str, uuids: list[str]) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            self._conn.execute(
                "INSERT INTO batches (id, created_at, status, uuid_count) VALUES (?, ?, 'running', ?)",
                (batch_id, now_iso(), len(uuids)),
            )
            self._conn.executemany(
                "INSERT INTO batch_uuids (batch_id, uuid, updated_at) VALUES (?, ?, ?)",
                [(batch_id, u, now_iso()) for u in uuids],
            )
            self._conn.execute("COMMIT")

    def set_batch_status(self, batch_id: str, status: str, error: str | None = None) -> None:
        self.execute("UPDATE batches SET status = ?, error = ? WHERE id = ?", (status, error, batch_id))

    def set_uuid_status(self, batch_id: str, uuid: str, status: str, *, error: str | None = None) -> None:
        self.execute(
            "UPDATE batch_uuids SET status = ?, error = ?, updated_at = ? WHERE batch_id = ? AND uuid = ?",
            (status, error, now_iso(), batch_id, uuid),
        )

    def batch_uuids(self, batch_id: str) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM batch_uuids WHERE batch_id = ? ORDER BY rowid", (batch_id,)
        )

    def batches(self) -> list[sqlite3.Row]:
        return self.query(
            """SELECT b.*,
                      SUM(CASE WHEN u.status IN ('done','no_events','unknown','failed') THEN 1 ELSE 0 END) AS finished,
                      SUM(u.events) AS events
               FROM batches b LEFT JOIN batch_uuids u ON u.batch_id = b.id
               GROUP BY b.id ORDER BY b.created_at DESC"""
        )

    def purge_batch(self, batch_id: str) -> int:
        """Delete the batch; events of uuids no other batch still references go with it."""
        with self._lock:
            self._conn.execute("BEGIN")
            orphans = [
                r["uuid"] for r in self._conn.execute(
                    """SELECT uuid FROM batch_uuids WHERE batch_id = ?
                       AND uuid NOT IN (SELECT uuid FROM batch_uuids WHERE batch_id != ?)""",
                    (batch_id, batch_id),
                )
            ]
            deleted = 0
            for u in orphans:
                deleted += self._conn.execute("DELETE FROM events WHERE player_uuid = ?", (u,)).rowcount
            self._conn.execute("DELETE FROM batch_uuids WHERE batch_id = ?", (batch_id,))
            self._conn.execute("DELETE FROM batches WHERE id = ?", (batch_id,))
            self._conn.execute("COMMIT")
        return deleted

    # -- events -------------------------------------------------------------
    def insert_events_page(self, batch_id: str, uuid: str, events: list[dict[str, Any]],
                           page: int, has_more: bool) -> int:
        """Commit one page atomically with the uuid's progress (resume point)."""
        rows = []
        for e in events:
            if PII_KEYS & set(e):
                raise ValueError("PII reached the store — client must strip it")
            vals = [("" if e.get(c) is None else str(e.get(c))) for c in EVENT_COLUMNS]
            # created_at: keep "YYYY-MM-DD HH:MM:SS" whatever separator the source used
            vals[-1] = vals[-1].replace("T", " ")[:19]
            rows.append((uuid, *vals))
        with self._lock:
            self._conn.execute("BEGIN")
            before = self._conn.total_changes
            self._conn.executemany(
                "INSERT OR IGNORE INTO events (player_uuid, " + ", ".join(EVENT_COLUMNS) + ") VALUES (?" + ", ?" * len(EVENT_COLUMNS) + ")",
                rows,
            )
            inserted = self._conn.total_changes - before
            total = self._conn.execute(
                "SELECT COUNT(*) FROM events WHERE player_uuid = ?", (uuid,)
            ).fetchone()[0]
            self._conn.execute(
                """UPDATE batch_uuids SET pages_done = ?, has_more = ?, events = ?, status = ?, updated_at = ?
                   WHERE batch_id = ? AND uuid = ?""",
                (page, int(has_more), total, "fetching" if has_more else "done", now_iso(), batch_id, uuid),
            )
            self._conn.execute("COMMIT")
        return inserted

    def events_for(self, uuid: str) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM events WHERE player_uuid = ? ORDER BY created_at ASC, frontend_session_uuid, rowid",
            (uuid,),
        )

    def distinct_ips(self, uuid: str) -> list[str]:
        return [r[0] for r in self.query(
            "SELECT DISTINCT ip_address FROM events WHERE player_uuid = ? AND ip_address != ''", (uuid,)
        )]

    def distinct_uas(self, uuid: str) -> list[str]:
        return [r[0] for r in self.query(
            "SELECT DISTINCT user_agent FROM events WHERE player_uuid = ? AND user_agent != ''", (uuid,)
        )]

    # -- enrichment caches ---------------------------------------------------
    def ip_rows(self, ips: list[str]) -> dict[str, sqlite3.Row]:
        if not ips:
            return {}
        q = "SELECT * FROM ips WHERE ip IN (" + ",".join("?" * len(ips)) + ")"
        return {r["ip"]: r for r in self.query(q, ips)}

    def ipqs_rows(self, ips: list[str]) -> dict[str, sqlite3.Row]:
        if not ips:
            return {}
        q = "SELECT * FROM ipqs WHERE ip IN (" + ",".join("?" * len(ips)) + ")"
        return {r["ip"]: r for r in self.query(q, ips)}

    def ua_rows(self, uas: list[str]) -> dict[str, sqlite3.Row]:
        if not uas:
            return {}
        q = "SELECT * FROM uas WHERE ua IN (" + ",".join("?" * len(uas)) + ")"
        return {r["ua"]: r for r in self.query(q, uas)}

    def ips_missing(self, ips: list[str], retry_after_seconds: int = 3600) -> list[str]:
        """IPs with no row, plus rows that recorded an error more than `retry_after_seconds` ago
        (a registry hiccup must not de-enrich an IP for ever)."""
        have = self.ip_rows(ips)
        cutoff = (datetime.now(UTC) - timedelta(seconds=retry_after_seconds)).strftime("%Y-%m-%d %H:%M:%S")
        out = []
        for ip in dict.fromkeys(ips):
            r = have.get(ip)
            if r is None or (r["error"] and (r["fetched_at"] or "") <= cutoff):
                out.append(ip)
        return out

    def batch_ip_stats(self, uuids: list[str]) -> tuple[int, int]:
        """(distinct IPs across the batch, of which enriched without error) — for the progress bar."""
        if not uuids:
            return (0, 0)
        marks = ",".join("?" * len(uuids))
        total = self.one(
            f"SELECT COUNT(DISTINCT ip_address) FROM events WHERE player_uuid IN ({marks}) AND ip_address != ''",
            uuids)[0]
        enriched = self.one(
            f"""SELECT COUNT(DISTINCT e.ip_address) FROM events e JOIN ips i ON i.ip = e.ip_address
                 WHERE e.player_uuid IN ({marks}) AND e.ip_address != '' AND i.error IS NULL""", uuids)[0]
        return (int(total), int(enriched))

    def distinct_ip_counts(self, uuids: list[str]) -> dict[str, int]:
        if not uuids:
            return {}
        q = ("SELECT player_uuid, COUNT(DISTINCT ip_address) AS n FROM events WHERE player_uuid IN ("
             + ",".join("?" * len(uuids)) + ") GROUP BY player_uuid")
        return {r["player_uuid"]: int(r["n"]) for r in self.query(q, uuids)}

    def save_ip(self, ip: str, **fields: Any) -> None:
        cols = ["ip", "fetched_at", *fields]
        vals = [ip, now_iso(), *fields.values()]
        self.execute(
            f"INSERT OR REPLACE INTO ips ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", vals
        )

    def save_ua(self, ua: str, browser: str, browser_major: str, os: str, os_version: str, device: str) -> None:
        self.execute(
            "INSERT OR REPLACE INTO uas (ua, browser, browser_major, os, os_version, device, parsed_at) VALUES (?,?,?,?,?,?,?)",
            (ua, browser, browser_major, os, os_version, device, now_iso()),
        )

    def save_ipqs(self, ip: str, payload: dict[str, Any]) -> None:
        def b(k: str) -> int | None:
            v = payload.get(k)
            return None if v is None else int(bool(v))
        with self._lock:
            self._conn.execute("BEGIN")
            self._conn.execute(
                """INSERT OR REPLACE INTO ipqs (ip, json, fetched_at, fraud_score, connection_type, isp,
                   organization, asn, proxy, vpn, tor, active_vpn, active_tor, recent_abuse, bot_status, country_code)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ip, json.dumps(payload), now_iso(), payload.get("fraud_score"),
                 payload.get("connection_type"), payload.get("ISP"), payload.get("organization"),
                 payload.get("ASN"), b("proxy"), b("vpn"), b("tor"), b("active_vpn"), b("active_tor"),
                 b("recent_abuse"), b("bot_status"), payload.get("country_code")),
            )
            self._conn.execute("INSERT INTO ipqs_log (ip, fetched_at, success) VALUES (?, ?, 1)", (ip, now_iso()))
            self._conn.execute("DELETE FROM ipqs_errors WHERE ip = ?", (ip,))
            self._conn.execute("COMMIT")

    def log_ipqs_failure(self, ip: str, error: str, *, charged: bool) -> None:
        """Record the failure for the page; count it against the day only if IPQS processed it."""
        with self._lock:
            self._conn.execute("BEGIN")
            self._conn.execute("INSERT OR REPLACE INTO ipqs_errors (ip, error, attempted_at) VALUES (?, ?, ?)",
                               (ip, error[:300], now_iso()))
            if charged:
                self._conn.execute("INSERT INTO ipqs_log (ip, fetched_at, success) VALUES (?, ?, 0)", (ip, now_iso()))
            self._conn.execute("COMMIT")

    def ipqs_error_rows(self, ips: list[str]) -> dict[str, sqlite3.Row]:
        if not ips:
            return {}
        q = "SELECT * FROM ipqs_errors WHERE ip IN (" + ",".join("?" * len(ips)) + ")"
        return {r["ip"]: r for r in self.query(q, ips)}

    def ipqs_spent_today(self) -> int:
        day = datetime.now(UTC).strftime("%Y-%m-%d")
        row = self.one("SELECT COUNT(*) FROM ipqs_log WHERE fetched_at >= ?", (day + " 00:00:00",))
        return int(row[0]) if row else 0

    # -- kv ------------------------------------------------------------------
    def kv_get(self, key: str) -> tuple[str, str] | None:
        r = self.one("SELECT value, updated_at FROM kv WHERE key = ?", (key,))
        return (r["value"], r["updated_at"]) if r else None

    def kv_set(self, key: str, value: str) -> None:
        self.execute("INSERT OR REPLACE INTO kv (key, value, updated_at) VALUES (?, ?, ?)", (key, value, now_iso()))
