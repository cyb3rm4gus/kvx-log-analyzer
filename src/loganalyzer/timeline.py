"""Account view model: summary card + timeline rows with IP / UA change markers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .db import Database
from .enrich.ua import Parsed, describe, ua_change


@dataclass
class Filters:
    session: str = ""
    ip: str = ""
    path: str = ""
    date_from: str = ""
    date_to: str = ""

    def active(self) -> bool:
        return any((self.session, self.ip, self.path, self.date_from, self.date_to))


@dataclass
class Row:
    created_at: str
    day: str
    time: str
    session: str
    session_short: str
    path: str
    referrer: str
    ip: str
    country: str
    language: str
    ua: str
    ua_desc: str
    click_id: str
    ip_changed: bool = False
    prev_ip: str = ""
    ua_change: str | None = None
    prev_ua_desc: str = ""
    ip_info: dict[str, Any] = field(default_factory=dict)
    ipqs: dict[str, Any] = field(default_factory=dict)


def url_path(url: str) -> str:
    if not url:
        return ""
    try:
        s = urlsplit(url)
    except ValueError:
        return url
    if not s.scheme and not s.netloc:
        return url
    return (s.path or "/") + (f"?{s.query}" if s.query else "")


def _row_dict(r: Any) -> dict[str, Any]:
    return dict(r) if r is not None else {}


def build_account_view(db: Database, uuid: str, filters: Filters | None = None) -> dict[str, Any]:
    filters = filters or Filters()
    events = db.events_for(uuid)  # chronological
    ips = db.distinct_ips(uuid)
    uas = db.distinct_uas(uuid)
    ip_info = db.ip_rows(ips)
    ipqs = db.ipqs_rows(ips)
    ipqs_err = db.ipqs_error_rows(ips)
    ua_info = db.ua_rows(uas)

    def parsed(ua: str) -> Parsed | None:
        r = ua_info.get(ua)
        if not r:
            return None
        return (r["browser"] or "Other", r["browser_major"] or "", r["os"] or "Other",
                r["os_version"] or "", r["device"] or "Other")

    rows: list[Row] = []
    prev_ip = prev_ua = ""
    prev_parsed: Parsed | None = None
    ip_counter: Counter[str] = Counter()
    ua_counter: Counter[str] = Counter()
    country_counter: Counter[str] = Counter()
    sessions: set[str] = set()
    ip_span: dict[str, list[str]] = {}
    ua_span: dict[str, list[str]] = {}
    for e in events:
        ip, ua = e["ip_address"], e["user_agent"]
        p = parsed(ua)
        row = Row(
            created_at=e["created_at"], day=e["created_at"][:10], time=e["created_at"][11:19],
            session=e["frontend_session_uuid"], session_short=e["frontend_session_uuid"][:8],
            path=url_path(e["url"]), referrer=e["referrer_url"], ip=ip, country=e["country"],
            language=e["language"], ua=ua, ua_desc=describe(p) if p else (ua[:60] if ua else ""),
            click_id=e["click_id"],
            ip_info=_row_dict(ip_info.get(ip)), ipqs=_row_dict(ipqs.get(ip)),
        )
        if rows:
            if ip != prev_ip:
                row.ip_changed, row.prev_ip = True, prev_ip
            if ua != prev_ua:
                change = ua_change(prev_parsed, p)
                if change is None and (prev_parsed is None or p is None):
                    change = "major"  # unparsed but different strings: treat as a real change
                row.ua_change = change
                row.prev_ua_desc = describe(prev_parsed) if prev_parsed else prev_ua[:60]
        rows.append(row)
        prev_ip, prev_ua, prev_parsed = ip, ua, p
        ip_counter[ip] += 1
        ua_counter[ua] += 1
        if e["country"]:
            country_counter[e["country"]] += 1
        sessions.add(e["frontend_session_uuid"])
        ip_span.setdefault(ip, [e["created_at"], e["created_at"]])[1] = e["created_at"]
        ua_span.setdefault(ua, [e["created_at"], e["created_at"]])[1] = e["created_at"]

    # filters, applied after markers are computed so a filtered view keeps true change context
    def keep(r: Row) -> bool:
        if filters.session and r.session != filters.session:
            return False
        if filters.ip and r.ip != filters.ip:
            return False
        if filters.path and filters.path.lower() not in r.path.lower():
            return False
        if filters.date_from and r.day < filters.date_from:
            return False
        return not (filters.date_to and r.day > filters.date_to)

    shown = [r for r in rows if keep(r)]
    shown.reverse()  # newest first, the warehouse order
    # grouped by day, then by consecutive session (spec §5 item 3)
    days: list[tuple[str, list[tuple[str, list[Row]]]]] = []
    for r in shown:
        if not days or days[-1][0] != r.day:
            days.append((r.day, []))
        groups = days[-1][1]
        if not groups or groups[-1][0] != r.session:
            groups.append((r.session, []))
        groups[-1][1].append(r)

    ip_cards = [
        {"ip": ip, "count": n, "first": ip_span[ip][0], "last": ip_span[ip][1],
         "info": _row_dict(ip_info.get(ip)), "ipqs": _row_dict(ipqs.get(ip)),
         "ipqs_error": _row_dict(ipqs_err.get(ip))}
        for ip, n in ip_counter.most_common()
    ]
    ua_cards = [
        {"ua": ua, "count": n, "first": ua_span[ua][0], "last": ua_span[ua][1],
         "desc": describe(parsed(ua)) if parsed(ua) else ua}
        for ua, n in ua_counter.most_common()
    ]
    membership = db.query(
        "SELECT batch_id, status, pages_done, has_more, error FROM batch_uuids WHERE uuid = ? ORDER BY updated_at DESC",
        (uuid,),
    )
    pages = max((m["pages_done"] for m in membership), default=0)
    return {
        "uuid": uuid,
        "events": len(rows),
        "shown": len(shown),
        "first_seen": rows[0].created_at if rows else None,
        "last_seen": rows[-1].created_at if rows else None,
        "sessions": len(sessions),
        "countries": country_counter.most_common(),
        "ips": ip_cards,
        "uas": ua_cards,
        "ip_changes": sum(1 for r in rows if r.ip_changed),
        "ua_changes": sum(1 for r in rows if r.ua_change),
        "enriched": sum(1 for ip in ips if ip in ip_info and not ip_info[ip]["error"]),
        "enrich_errors": sum(1 for ip in ips if ip in ip_info and ip_info[ip]["error"]),
        "ipqs_cached": sum(1 for ip in ips if ip in ipqs),
        "ipqs_pending": [ip for ip in ips if ip not in ipqs],
        "days": days,
        "caveat": pages > 1,
        "pages": pages,
        "membership": [dict(m) for m in membership],
        "filters": filters,
    }


def ipqs_context(db: Database, uuid: str, ip: str) -> tuple[str | None, str | None]:
    """Most-used user agent and language with this IP for this account (sent to IPQS, spec §3.3)."""
    r = db.one(
        """SELECT user_agent, language, COUNT(*) AS n FROM events
           WHERE player_uuid = ? AND ip_address = ? GROUP BY user_agent, language ORDER BY n DESC LIMIT 1""",
        (uuid, ip),
    )
    if not r:
        return None, None
    return (r["user_agent"] or None), (r["language"] or None)
