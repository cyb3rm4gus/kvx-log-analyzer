"""Pasted-uuid parsing: one per line, commas/whitespace tolerated, canonical UUID shape only."""

from __future__ import annotations

import re
from dataclasses import dataclass

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SPLIT_RE = re.compile(r"[\s,;]+")
MAX_UUIDS = 1000


@dataclass(frozen=True)
class ParsedUuids:
    uuids: list[str]      # normalised (lowercase), de-duplicated, in first-seen order
    rejected: list[str]   # tokens that are not a canonical uuid
    duplicates: int
    truncated: int = 0    # uuids beyond MAX_UUIDS, dropped (a few hundred is the settled size)


def parse_uuids(text: str) -> ParsedUuids:
    seen: set[str] = set()
    uuids: list[str] = []
    rejected: list[str] = []
    duplicates = 0
    for token in SPLIT_RE.split(text.strip()):
        if not token:
            continue
        cand = token.strip().strip("\"'").lower()
        if not UUID_RE.match(cand):
            rejected.append(token)
            continue
        if cand in seen:
            duplicates += 1
            continue
        seen.add(cand)
        uuids.append(cand)
    truncated = max(0, len(uuids) - MAX_UUIDS)
    return ParsedUuids(uuids=uuids[:MAX_UUIDS], rejected=rejected, duplicates=duplicates, truncated=truncated)
