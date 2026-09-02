"""Settings, from the environment (`.env` via compose)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    return int(raw) if raw else default


@dataclass(frozen=True)
class Settings:
    gh_api_url: str = "http://10.10.100.1:8080"
    gh_token: str = ""
    ipqs_key: str = ""
    db_path: str = "/data/loganalyzer.sqlite"
    gh_concurrency: int = 2
    #: IPQS plan cap per UTC day (owner ruling 3.3-b: 5 000/month Startup tier = 250/day).
    ipqs_daily_cap: int = 250
    #: Seconds between `readyz` probes while Guardhouse is unreachable, and how many
    #: probes before a paused uuid is failed (default: 30 s × 20 = 10 minutes).
    ready_poll_seconds: float = 30.0
    ready_poll_attempts: int = 20
    #: Minimum spacing between RDAP requests to one registry (1 req/s per spec §3.1).
    rdap_min_interval: float = 1.0
    #: Automatic enrichment (RDAP + ASN + UA) after a batch; tests switch it off.
    enrich: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            gh_api_url=os.environ.get("GH_API_URL", cls.gh_api_url).rstrip("/"),
            gh_token=os.environ.get("GH_TOKEN", "").strip(),
            ipqs_key=os.environ.get("IPQS_KEY", "").strip(),
            db_path=os.environ.get("LA_DB_PATH", cls.db_path),
            gh_concurrency=max(1, _int("LA_GH_CONCURRENCY", cls.gh_concurrency)),
            ipqs_daily_cap=max(1, _int("LA_IPQS_DAILY_CAP", cls.ipqs_daily_cap)),
            enrich=os.environ.get("LA_ENRICH", "1") != "0",
        )
