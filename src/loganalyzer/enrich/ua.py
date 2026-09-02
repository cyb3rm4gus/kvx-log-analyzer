"""User-Agent parsing and drift classification (spec §3.4)."""

from __future__ import annotations

from ua_parser import parse

Parsed = tuple[str, str, str, str, str]  # browser, browser_major, os, os_version, device


def parse_ua(ua: str) -> Parsed:
    r = parse(ua)
    b = r.user_agent
    o = r.os
    d = r.device
    browser = (b.family if b and b.family else "Other")
    major = (b.major if b and b.major else "")
    os_family = (o.family if o and o.family else "Other")
    os_version = ".".join(p for p in ((o.major if o else None), (o.minor if o else None)) if p) if o else ""
    device = (d.family if d and d.family else "Other")
    return browser, major, os_family, os_version, device


def _ver(s: str) -> tuple[int, ...]:
    out = []
    for part in s.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out)


def ua_change(prev: Parsed | None, cur: Parsed | None) -> str | None:
    """None (same); 'minor' (same browser/OS/device families, a version went UP — auto-update);
    'downgrade' (same families, a browser or OS version went DOWN — a spoofing signal an analyst
    wants to see); 'major' (browser family, OS family or device changed)."""
    if prev is None or cur is None or prev == cur:
        return None
    if (prev[0], prev[2], prev[4]) != (cur[0], cur[2], cur[4]):
        return "major"
    if _ver(cur[1]) < _ver(prev[1]) or _ver(cur[3]) < _ver(prev[3]):
        return "downgrade"
    return "minor"


def describe(p: Parsed) -> str:
    browser = f"{p[0]} {p[1]}".strip()
    os_ = f"{p[2]} {p[3]}".strip()
    dev = "" if p[4] in ("Other", "") else f" · {p[4]}"
    return f"{browser} on {os_}{dev}"
