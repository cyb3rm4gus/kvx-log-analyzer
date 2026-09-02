"""In-process batch runner (owner ruling 2.2-a): asyncio task per batch, 2 uuids at a time toward
Guardhouse, pages sequential within a uuid, every page committed (resume point), then the
automatic enrichment pass. Progress is streamed to the batch page over SSE.

Every wait is bounded (spec §1.4 "fails loud"): a uuid that Guardhouse keeps throttling, keeps
failing, or that the analyst's VPN keeps dropping ends as `failed` with the reason, and the
batch page offers "retry failed".

Paging is deterministic since Guardhouse appended the unique `id` to the `events_by_uuid`
ORDER BY (finding H3, fixed 2026-09-02): no rows are dropped at page boundaries any more. What
remains is an event arriving mid-pull shifting later pages by one — the store's uniqueness key
over all nine columns collapses that exact repeat."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from . import guardhouse as gh
from .config import Settings
from .db import Database
from .enrich import Enricher

log = logging.getLogger(__name__)

UPSTREAM_RETRIES = 3
UPSTREAM_BACKOFF = (2.0, 5.0, 15.0)
DEFAULT_RETRY_AFTER = 5.0
#: Total seconds a uuid may spend waiting on 429/503 before it is failed.
UNAVAILABLE_MAX_WAIT = 600.0
#: How many separate "Guardhouse unreachable → back" cycles a uuid gets before it is failed.
PAUSE_CYCLES_MAX = 3
RESUMABLE = ("queued", "fetching", "paused")


@dataclass
class Progress:
    seq: int
    message: str


@dataclass
class BatchJob:
    batch_id: str
    events: list[Progress] = field(default_factory=list)
    done: bool = False
    phase: str = "fetching"   # fetching → enriching → done
    task: asyncio.Task[None] | None = None
    _waiters: list[asyncio.Event] = field(default_factory=list)

    def emit(self, message: str) -> None:
        self.events.append(Progress(len(self.events), message))
        log.info("batch %s: %s", self.batch_id, message)
        for w in self._waiters:
            w.set()

    async def wait(self, after_seq: int) -> None:
        if len(self.events) > after_seq or self.done:
            return
        ev = asyncio.Event()
        self._waiters.append(ev)
        try:
            await asyncio.wait_for(ev.wait(), timeout=15.0)
        except TimeoutError:
            pass
        finally:
            self._waiters.remove(ev)


class JobRunner:
    def __init__(self, db: Database, client: gh.GuardhouseClient, settings: Settings,
                 enricher: Enricher | None = None) -> None:
        self.db = db
        self.client = client
        self.settings = settings
        self.enricher = enricher
        self.jobs: dict[str, BatchJob] = {}

    def start(self, batch_id: str, *, retry_failed: bool = False) -> BatchJob:
        job = self.jobs.get(batch_id)
        if job and not job.done:
            return job
        job = BatchJob(batch_id)
        self.jobs[batch_id] = job
        job.task = asyncio.create_task(self._run(job, retry_failed))
        return job

    async def _run(self, job: BatchJob, retry_failed: bool) -> None:
        batch_id = job.batch_id
        try:
            statuses = RESUMABLE + (("failed",) if retry_failed else ())
            rows = self.db.batch_uuids(batch_id)
            pending = [r["uuid"] for r in rows if r["status"] in statuses]
            self.db.set_batch_status(batch_id, "running")
            job.emit(f"processing {len(pending)} uuid(s), {self.settings.gh_concurrency} at a time")
            sem = asyncio.Semaphore(self.settings.gh_concurrency)
            auth_failed = asyncio.Event()

            async def one(uuid: str) -> None:
                async with sem:
                    if auth_failed.is_set():
                        self.db.set_uuid_status(batch_id, uuid, "failed", error="batch stopped: auth error")
                        return
                    await self._process_uuid(batch_id, uuid, job, auth_failed)

            await asyncio.gather(*(one(u) for u in pending))
            if auth_failed.is_set():
                self.db.set_batch_status(batch_id, "failed", "Guardhouse rejected the token (401/403)")
                job.emit("batch failed: Guardhouse rejected the token — check GH_TOKEN")
                return
            if self.settings.enrich and self.enricher:
                job.phase = "enriching"
                await self._enrich(batch_id, job)
            job.phase = "done"
            self.db.set_batch_status(batch_id, "done")
            failed = sum(1 for r in self.db.batch_uuids(batch_id) if r["status"] == "failed")
            job.emit("done" + (f" — {failed} uuid(s) failed, see the table (retry available)" if failed else ""))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.exception("batch %s crashed", batch_id)
            self.db.set_batch_status(batch_id, "failed", f"{exc.__class__.__name__}: {exc}")
            job.emit(f"batch failed: {exc.__class__.__name__}: {exc}")
        finally:
            job.done = True
            for w in job._waiters:
                w.set()

    async def _process_uuid(self, batch_id: str, uuid: str, job: BatchJob, auth_failed: asyncio.Event) -> None:
        row = self.db.one("SELECT pages_done, has_more FROM batch_uuids WHERE batch_id = ? AND uuid = ?",
                          (batch_id, uuid))
        page = int(row["pages_done"]) + 1 if row else 1
        if row and row["pages_done"] and not row["has_more"]:
            self.db.set_uuid_status(batch_id, uuid, "done")
            return
        self.db.set_uuid_status(batch_id, uuid, "fetching")
        short = uuid[:8]
        upstream_failures = 0
        waited = 0.0
        pause_cycles = 0
        while True:
            try:
                result = await self.client.events_page(uuid, page)
            except gh.NotFound:
                self.db.set_uuid_status(batch_id, uuid, "unknown", error="uuid unknown to Guardhouse (404)")
                job.emit(f"{short}: unknown uuid (404)")
                return
            except gh.AuthError as exc:
                auth_failed.set()
                self.db.set_uuid_status(batch_id, uuid, "failed", error=str(exc))
                return
            except gh.InvalidParam as exc:
                self.db.set_uuid_status(batch_id, uuid, "failed", error=str(exc))
                job.emit(f"{short}: rejected by Guardhouse ({exc})")
                return
            except gh.Desync as exc:
                self.db.set_uuid_status(batch_id, uuid, "no_events", error=str(exc))
                job.emit(f"{short}: player row but no events (source_desync)")
                return
            except gh.Unavailable as exc:
                wait = DEFAULT_RETRY_AFTER if exc.retry_after is None else exc.retry_after
                waited += wait
                if waited > UNAVAILABLE_MAX_WAIT:
                    self.db.set_uuid_status(batch_id, uuid, "failed",
                                            error=f"Guardhouse kept answering {exc.status} for {UNAVAILABLE_MAX_WAIT:.0f}s")
                    job.emit(f"{short}: failed — throttled by Guardhouse for over {UNAVAILABLE_MAX_WAIT:.0f}s")
                    return
                job.emit(f"{short}: Guardhouse says wait {wait:.0f}s ({exc.status})")
                await asyncio.sleep(wait)
                continue
            except gh.Upstream as exc:
                upstream_failures += 1
                if upstream_failures > UPSTREAM_RETRIES:
                    self.db.set_uuid_status(batch_id, uuid, "failed", error=str(exc))
                    job.emit(f"{short}: failed after {UPSTREAM_RETRIES} upstream errors ({exc})")
                    return
                backoff = UPSTREAM_BACKOFF[min(upstream_failures, len(UPSTREAM_BACKOFF)) - 1]
                job.emit(f"{short}: upstream error ({exc}), retry {upstream_failures} in {backoff:.0f}s")
                await asyncio.sleep(backoff)
                continue
            except gh.ConnectionLost as exc:
                pause_cycles += 1
                self.db.set_uuid_status(batch_id, uuid, "paused", error=str(exc))
                job.emit(f"{short}: Guardhouse unreachable — paused, probing readyz every "
                         f"{self.settings.ready_poll_seconds:.0f}s")
                if pause_cycles > PAUSE_CYCLES_MAX or not await self._wait_ready():
                    self.db.set_uuid_status(batch_id, uuid, "failed",
                                            error="Guardhouse unreachable (gave up; retry when the VPN is back)")
                    job.emit(f"{short}: gave up waiting for Guardhouse")
                    return
                self.db.set_uuid_status(batch_id, uuid, "fetching")
                job.emit(f"{short}: Guardhouse is back, resuming at page {page}")
                continue
            except gh.GuardhouseError as exc:
                self.db.set_uuid_status(batch_id, uuid, "failed", error=str(exc))
                job.emit(f"{short}: {exc}")
                return
            upstream_failures = 0
            if not result.events and result.has_more:
                # cannot happen under the contract; do not loop on it
                job.emit(f"{short}: empty page {page} claims more — stopping here")
                self.db.insert_events_page(batch_id, uuid, [], page, has_more=False)
                return
            self.db.insert_events_page(batch_id, uuid, result.events, page, result.has_more)
            total = self.db.one("SELECT events FROM batch_uuids WHERE batch_id = ? AND uuid = ?", (batch_id, uuid))
            job.emit(f"{short}: page {page} ({int(total['events']) if total else 0} events)")
            if not result.has_more:
                if page == 1 and not result.events:
                    self.db.set_uuid_status(batch_id, uuid, "no_events")
                return
            page += 1

    async def _wait_ready(self) -> bool:
        for _ in range(self.settings.ready_poll_attempts):
            await asyncio.sleep(self.settings.ready_poll_seconds)
            if await self.client.ready():
                return True
        return False

    async def _enrich(self, batch_id: str, job: BatchJob) -> None:
        assert self.enricher
        uuids = [r["uuid"] for r in self.db.batch_uuids(batch_id)]
        ips: dict[str, None] = {}
        uas: dict[str, None] = {}
        for u in uuids:
            ips.update(dict.fromkeys(self.db.distinct_ips(u)))
            uas.update(dict.fromkeys(self.db.distinct_uas(u)))
        n_ua = self.enricher.enrich_uas(list(uas))
        missing = len(self.db.ips_missing(list(ips)))
        job.emit(f"enrichment: {len(uas)} user agents parsed ({n_ua} new); {missing} of {len(ips)} IPs to look up")
        if missing:
            await self.enricher.enrich_ips(list(ips), job.emit)
