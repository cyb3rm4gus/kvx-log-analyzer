"""Batch export: one JSON file per uuid with its events exactly as Guardhouse returns them (the
nine event columns, newest first, nothing else), packed into `export_<alias>.tar.gz`."""

from __future__ import annotations

import io
import json
import re
import tarfile
import time

from .db import EVENT_COLUMNS, Database

SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(alias: str | None, fallback: str) -> str:
    name = SAFE.sub("_", (alias or "").strip()).strip("._")
    return name or fallback


def build_export(db: Database, batch_id: str) -> tuple[str, bytes]:
    """Return (archive file name, tar.gz bytes) for the batch."""
    batch = db.one("SELECT alias FROM batches WHERE id = ?", (batch_id,))
    label = safe_name(batch["alias"] if batch else None, batch_id)
    buf = io.BytesIO()
    now = int(time.time())
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for row in db.batch_uuids(batch_id):
            uuid = row["uuid"]
            events = [{c: r[c] for c in EVENT_COLUMNS} for r in db.events_for_export(uuid)]
            data = json.dumps(events, ensure_ascii=False, indent=2).encode("utf-8")
            info = tarfile.TarInfo(name=f"export_{label}_{uuid}.json")
            info.size = len(data)
            info.mtime = now
            tar.addfile(info, io.BytesIO(data))
    return f"export_{label}.tar.gz", buf.getvalue()
