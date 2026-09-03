"""Account view model: summary card + timeline rows with IP / UA change markers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from .db import Database
from .enrich.ua import Parsed, describe, parse_ua, ua_change

UA_CHANGE_LABEL = {"minor": "upgrade", "downgrade": "downgrade", "major": "browser/OS change"}
#: change kinds a row can carry; the Changes section's checkboxes use these keys
CHANGE_KINDS = (("downgrade", "UA downgrade"), ("upgrade", "UA upgrade"), ("major", "browser/OS change"),
                ("asn", "ASN change"), ("asn_unknown", "IP change, ASN unknown"))
ALL_KINDS = frozenset(k for k, _ in CHANGE_KINDS)


@dataclass
class Filters:
    session: str = ""
    ip: str = ""
    path: str = ""
    date_from: str = ""
    date_to: str = ""
    #: Changes section only: year ("" = all), kinds shown (None = all), whether the selected
    #: kinds must all be on the same event, and the minimum browser major-version jump for an
    #: upgrade/downgrade to count (1 = any)
    changes_year: str = ""
    kinds: frozenset[str] | None = None
    combine: bool = False
    min_delta: int = 1

    def active(self) -> bool:
        return any((self.session, self.ip, self.path, self.date_from, self.date_to))

    def selected_kinds(self) -> frozenset[str]:
        return ALL_KINDS if self.kinds is None else self.kinds

    def timeline_qs(self, exclude: tuple[str, ...] = ("cy",)) -> str:
        """Query string of the current filters (timeline + Changes), minus `exclude` — so the year
        buttons keep the kind/threshold choices and the kind form keeps the year."""
        from urllib.parse import urlencode
        pairs: list[tuple[str, str]] = [("session", self.session), ("ip", self.ip), ("path", self.path),
                                        ("from", self.date_from), ("to", self.date_to), ("cy", self.changes_year)]
        if self.kinds is not None:
            pairs.append(("kf", "1"))
            pairs.extend(("k", k) for k, _ in CHANGE_KINDS if k in self.kinds)
        if self.combine:
            pairs.append(("combine", "1"))
        if self.min_delta > 1:
            pairs.append(("delta", str(self.min_delta)))
        return urlencode([(k, v) for k, v in pairs if v and k not in exclude])


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
    prev_ua: str = ""
    #: signed browser major-version jump (cur − prev) for an upgrade/downgrade; None when not comparable
    ua_delta: int | None = None
    #: where the user was on the previous event (the "before" side of a change)
    prev_path: str = ""
    prev_referrer: str = ""
    prev_session_short: str = ""
    prev_time: str = ""
    asn: int | None = None
    prev_asn: int | None = None
    as_name: str = ""
    prev_as_name: str = ""
    #: True = ASN differs from the previous event's; False = same; None = unknown (an IP not enriched)
    asn_changed: bool | None = None
    #: the change kinds this row carries under the current threshold (what the Kind column shows)
    kinds: set[str] = field(default_factory=set)
    ip_info: dict[str, Any] = field(default_factory=dict)
    ipqs: dict[str, Any] = field(default_factory=dict)

    @property
    def both(self) -> bool:
        return bool(self.ua_change) and self.asn_changed is True


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
        if not ua:
            return None
        r = ua_info.get(ua)
        if not r:
            # an existing batch whose enrichment pass has not parsed this UA yet: parse now, keep it
            p = parse_ua(ua)
            db.save_ua(ua, *p)
            ua_info[ua] = {"browser": p[0], "browser_major": p[1], "os": p[2], "os_version": p[3], "device": p[4]}
            return p
        return (r["browser"] or "Other", r["browser_major"] or "", r["os"] or "Other",
                r["os_version"] or "", r["device"] or "Other")

    def asn_of(ip: str) -> tuple[int | None, str]:
        r = ip_info.get(ip)
        if not r or r["asn"] is None:
            return None, ""
        return int(r["asn"]), r["as_name"] or ""

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
        row.asn, row.as_name = asn_of(ip)
        if rows:
            prev = rows[-1]
            row.prev_path, row.prev_referrer = prev.path, prev.referrer
            row.prev_session_short, row.prev_time = prev.session_short, prev.created_at
            if ip != prev_ip:
                row.ip_changed, row.prev_ip = True, prev_ip
                row.prev_asn, row.prev_as_name = asn_of(prev_ip)
                if row.asn is None or row.prev_asn is None:
                    row.asn_changed = None          # cannot say until both IPs are enriched
                else:
                    row.asn_changed = row.asn != row.prev_asn
            else:
                row.asn_changed = False
            if ua != prev_ua:
                change = ua_change(prev_parsed, p)
                if change is None and (prev_parsed is None or p is None):
                    change = "major"  # unparsed but different strings: treat as a real change
                row.ua_change = change
                row.ua_delta = major_delta(prev_parsed, p) if change in ("minor", "downgrade") else None
                row.prev_ua = prev_ua
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
    # the dedicated "changes" section: every UA change, every ASN change (or IP change whose ASN is
    # not known yet), and the combination — chronological, with the full UA strings
    all_changes = [r for r in rows if r.ua_change or r.asn_changed or (r.ip_changed and r.asn_changed is None)]
    change_years = sorted({r.day[:4] for r in all_changes}, reverse=True)
    changes = [r for r in all_changes if not filters.changes_year or r.day[:4] == filters.changes_year]
    for r in changes:
        r.kinds = row_kinds(r, filters.min_delta)
    changes = [r for r in changes if change_matches(r, filters)]
    counts = {
        "ua_upgrade": sum(1 for r in changes if r.ua_change == "minor"),
        "ua_downgrade": sum(1 for r in changes if r.ua_change == "downgrade"),
        "ua_major": sum(1 for r in changes if r.ua_change == "major"),
        "asn": sum(1 for r in changes if r.asn_changed is True),
        "asn_unknown": sum(1 for r in changes if r.ip_changed and r.asn_changed is None),
        "both": sum(1 for r in changes if r.both),
        "total": len(all_changes),
    }
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
        "changes": changes,
        "change_counts": counts,
        "change_years": change_years,
        "change_kinds": CHANGE_KINDS,
        "ua_change_label": UA_CHANGE_LABEL,
        "pages": pages,
        "membership": [dict(m) for m in membership],
        "filters": filters,
    }


def major_delta(prev: Parsed | None, cur: Parsed | None) -> int | None:
    """cur − prev browser major version, when both parse to numbers and the family is the same."""
    if not prev or not cur or prev[0] != cur[0]:
        return None
    try:
        return int(cur[1]) - int(prev[1])
    except ValueError:
        return None


def row_kinds(r: Row, min_delta: int = 1) -> set[str]:
    """The change kinds a row carries, after the major-version threshold: an upgrade/downgrade
    whose jump is smaller than `min_delta` majors does not count (150→144 counts at 3; 145→144 not)."""
    kinds: set[str] = set()
    if r.ua_change == "major":
        kinds.add("major")
    elif r.ua_change in ("minor", "downgrade"):
        if min_delta <= 1 or (r.ua_delta is not None and abs(r.ua_delta) >= min_delta):
            kinds.add("upgrade" if r.ua_change == "minor" else "downgrade")
    if r.asn_changed is True:
        kinds.add("asn")
    elif r.ip_changed and r.asn_changed is None:
        kinds.add("asn_unknown")
    return kinds


def change_matches(r: Row, f: Filters) -> bool:
    selected = f.selected_kinds()
    kinds = row_kinds(r, f.min_delta)
    if f.combine:
        return bool(selected) and selected <= kinds      # every selected kind on this same event
    return bool(selected & kinds)                        # any selected kind


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


def batch_flags(db: Database, uuids: list[str]) -> dict[str, dict[str, int]]:
    """Per-uuid change counts for the batch table (UA downgrades, other UA changes, ASN changes,
    both-at-once), computed in one pass over the batch's stored events. Works on an existing
    batch: UAs not yet parsed by the enrichment pass are parsed and saved on the way."""
    if not uuids:
        return {}
    marks = ",".join("?" * len(uuids))
    rows = db.query(
        f"""SELECT player_uuid, created_at, frontend_session_uuid, user_agent, ip_address FROM events
            WHERE player_uuid IN ({marks}) ORDER BY player_uuid, created_at, frontend_session_uuid, rowid""",
        uuids,
    )
    uas = list({r["user_agent"] for r in rows if r["user_agent"]})
    ips = list({r["ip_address"] for r in rows if r["ip_address"]})
    ua_info = db.ua_rows(uas)
    ip_info = db.ip_rows(ips)
    parsed_cache: dict[str, Parsed | None] = {}

    def parsed(ua: str) -> Parsed | None:
        if not ua:
            return None
        if ua in parsed_cache:
            return parsed_cache[ua]
        r = ua_info.get(ua)
        if r:
            p: Parsed = (r["browser"] or "Other", r["browser_major"] or "", r["os"] or "Other",
                         r["os_version"] or "", r["device"] or "Other")
        else:
            p = parse_ua(ua)
            db.save_ua(ua, *p)
        parsed_cache[ua] = p
        return p

    def asn(ip: str) -> int | None:
        r = ip_info.get(ip)
        return None if not r or r["asn"] is None else int(r["asn"])

    out: dict[str, dict[str, int]] = {u: {"ua_downgrade": 0, "ua_other": 0, "asn": 0, "both": 0} for u in uuids}
    cur = None
    prev_ua = prev_ip = ""
    for r in rows:
        u = r["player_uuid"]
        if u != cur:
            cur, prev_ua, prev_ip = u, r["user_agent"], r["ip_address"]
            continue
        ua, ip = r["user_agent"], r["ip_address"]
        change = None
        if ua != prev_ua:
            change = ua_change(parsed(prev_ua), parsed(ua)) or "major"
        a_changed = False
        if ip != prev_ip:
            a, b = asn(prev_ip), asn(ip)
            a_changed = a is not None and b is not None and a != b
        f = out[u]
        if change == "downgrade":
            f["ua_downgrade"] += 1
        elif change:
            f["ua_other"] += 1
        if a_changed:
            f["asn"] += 1
        if change and a_changed:
            f["both"] += 1
        prev_ua, prev_ip = ua, ip
    return out
