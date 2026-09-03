"""Routes: home (paste + batches), batch (progress, SSE), account (timeline, IPQS), purge, health."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates

from ..enrich.ipqs import IPQSError
from ..timeline import ALL_KINDS, Filters, batch_flags, build_account_view, ipqs_context
from ..uuids import UUID_RE, parse_uuids

log = logging.getLogger(__name__)
router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

ACCOUNT_CACHE_SECONDS = 600

#: uuid/batch status → a Tabler *native* light badge (readable: light bg, matching text colour).
STATUS_BADGE = {
    "queued": "bg-secondary-lt", "fetching": "bg-azure-lt", "running": "bg-azure-lt",
    "paused": "bg-yellow-lt", "enriching": "bg-azure-lt", "done": "bg-green-lt",
    "no_events": "bg-yellow-lt", "unknown": "bg-orange-lt", "failed": "bg-red-lt",
}
TERMINAL = frozenset({"done", "no_events", "unknown", "failed"})
templates.env.globals["STATUS_BADGE"] = STATUS_BADGE


@dataclass
class IpqsRun:
    uuid: str
    total: int
    done: int = 0
    failed: int = 0
    finished: bool = False
    capped: int = 0
    errors: list[str] = field(default_factory=list)
    task: asyncio.Task[None] | None = None


def render(request: Request, name: str, status: int = 200, **ctx: Any) -> HTMLResponse:
    ctx.setdefault("request", request)
    return templates.TemplateResponse(request, name, ctx, status_code=status)


def _state(request: Request) -> Any:
    return request.app.state


@router.get("/healthz")
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    st = _state(request)
    return render(request, "home.html", batches=st.db.batches(), settings=st.settings,
                  gh_configured=bool(st.settings.gh_token), ipqs_configured=bool(st.settings.ipqs_key))


@router.post("/batches")
async def create_batch(request: Request, uuids: str = Form("")) -> Any:
    st = _state(request)
    parsed = parse_uuids(uuids)
    if not parsed.uuids:
        return render(request, "home.html", batches=st.db.batches(), settings=st.settings,
                      gh_configured=bool(st.settings.gh_token), ipqs_configured=bool(st.settings.ipqs_key),
                      error="No valid uuids in the paste.", rejected=parsed.rejected, pasted=uuids)
    batch_id = time.strftime("%Y%m%d-%H%M%S", time.gmtime()) + "-" + secrets.token_hex(2)
    st.db.create_batch(batch_id, parsed.uuids)
    st.runner.start(batch_id)
    q = ""
    if parsed.rejected or parsed.duplicates or parsed.truncated:
        q = f"?rejected={len(parsed.rejected)}&duplicates={parsed.duplicates}&truncated={parsed.truncated}"
    return RedirectResponse(f"/batches/{batch_id}{q}", status_code=303)


@router.get("/batches/{batch_id}", response_class=HTMLResponse)
async def batch_page(request: Request, batch_id: str) -> Any:
    st = _state(request)
    batch = st.db.one("SELECT * FROM batches WHERE id = ?", (batch_id,))
    if not batch:
        return render(request, "error.html", message="No such batch.", status=404)
    rows = st.db.batch_uuids(batch_id)
    job = st.runner.jobs.get(batch_id)
    live = job is not None and not job.done
    if batch["status"] == "running" and not live:
        # process restarted mid-batch: resume from the committed pages
        st.runner.start(batch_id)
        live = True
    uuids = [r["uuid"] for r in rows]
    ip_counts = st.db.distinct_ip_counts(uuids)
    flags = batch_flags(st.db, uuids)
    failed = sum(1 for r in rows if r["status"] == "failed")
    return render(request, "batch.html", batch=batch, rows=rows, live=live, ip_counts=ip_counts, flags=flags,
                  failed=failed,
                  rejected=request.query_params.get("rejected"),
                  duplicates=request.query_params.get("duplicates"),
                  truncated=request.query_params.get("truncated"))


@router.post("/batches/{batch_id}/retry")
async def retry_failed(request: Request, batch_id: str) -> Any:
    """Re-queue the failed uuids of a batch (they resume from their last committed page)."""
    st = _state(request)
    if not st.db.one("SELECT 1 FROM batches WHERE id = ?", (batch_id,)):
        return render(request, "error.html", message="No such batch.", status=404)
    st.runner.start(batch_id, retry_failed=True)
    return RedirectResponse(f"/batches/{batch_id}", status_code=303)


@router.get("/batches/{batch_id}/status")
async def batch_status(request: Request, batch_id: str) -> JSONResponse:
    """Live JSON the batch page polls: per-uuid status/pages/events/IPs, phase, enrichment progress,
    and the recent log. Fixes the frozen table — the uuid rows and the enrichment phase now update
    without waiting for the whole job (enrichment of thousands of IPs is slow) to finish."""
    st = _state(request)
    batch = st.db.one("SELECT * FROM batches WHERE id = ?", (batch_id,))
    if not batch:
        return JSONResponse({"error": "no such batch"}, status_code=404)
    rows = st.db.batch_uuids(batch_id)
    uuids = [r["uuid"] for r in rows]
    ip_counts = st.db.distinct_ip_counts(uuids)
    flags = batch_flags(st.db, uuids)
    job = st.runner.jobs.get(batch_id)
    live = job is not None and not job.done
    all_terminal = all(r["status"] in TERMINAL for r in rows)
    if job and job.phase == "enriching":
        phase = "enriching"
    elif live:
        phase = "enriching" if all_terminal else "fetching"
    else:
        phase = batch["status"]
    enrich = None
    if phase == "enriching" or (batch["status"] == "done"):
        total, done = st.db.batch_ip_stats(uuids)
        enrich = {"done": done, "total": total}
    return JSONResponse({
        "batch_status": batch["status"], "phase": phase, "live": live,
        "enrich": enrich,
        "uuids": [{"uuid": r["uuid"], "status": r["status"], "pages": r["pages_done"],
                   "events": r["events"], "ips": ip_counts.get(r["uuid"], 0),
                   "flags": flags.get(r["uuid"], {}),
                   "error": r["error"] or ""} for r in rows],
        "log": [p.message for p in (job.events[-200:] if job else [])],
        "badge": STATUS_BADGE,
    })


@router.get("/batches/{batch_id}/events")
async def batch_events(request: Request, batch_id: str) -> StreamingResponse:
    st = _state(request)
    job = st.runner.jobs.get(batch_id)

    async def stream() -> Any:
        if job is None:
            yield "event: end\ndata: {}\n\n"
            return
        seq = 0
        while True:
            while seq < len(job.events):
                p = job.events[seq]
                yield f"data: {json.dumps({'seq': p.seq, 'message': p.message})}\n\n"
                seq += 1
            if job.done:
                yield "event: end\ndata: {}\n\n"
                return
            await job.wait(seq)
            yield ": keepalive\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.post("/batches/{batch_id}/purge")
async def purge_batch(request: Request, batch_id: str) -> RedirectResponse:
    st = _state(request)
    job = st.runner.jobs.get(batch_id)
    if job and not job.done and job.task:
        job.task.cancel()
    deleted = st.db.purge_batch(batch_id)
    log.info("purged batch %s (%d orphaned events removed)", batch_id, deleted)
    return RedirectResponse("/", status_code=303)


@router.get("/accounts/{uuid}", response_class=HTMLResponse)
async def account_page(request: Request, uuid: str) -> Any:
    st = _state(request)
    uuid = uuid.lower()
    if not UUID_RE.match(uuid):
        return render(request, "error.html", message="Not a uuid.", status=404)
    qp = request.query_params
    kinds = frozenset(k for k in qp.getlist("k") if k in ALL_KINDS) if qp.get("kf") == "1" else None
    delta_raw = qp.get("delta", "")
    filters = Filters(session=qp.get("session", ""), ip=qp.get("ip", ""), path=qp.get("path", ""),
                      date_from=qp.get("from", ""), date_to=qp.get("to", ""),
                      changes_year=qp.get("cy", "")[:4] if qp.get("cy", "").isdigit() else "",
                      kinds=kinds, combine=qp.get("combine") == "1",
                      min_delta=max(1, min(999, int(delta_raw))) if delta_raw.isdigit() else 1)
    view = build_account_view(st.db, uuid, filters)
    run = st.ipqs_runs.get(uuid)
    spent = st.db.ipqs_spent_today()
    remaining_today = max(0, st.settings.ipqs_daily_cap - spent)
    # Credits come from the cache the last press filled — the deliverable page never calls the
    # paid vendor itself (spec §3.3: nothing automatic, and the page renders as soon as events are in).
    cache = st.ipqs_account_cache
    credits = cache[1].get("credits") if cache and cache[1] else None
    return render(request, "account.html", v=view, run=run, ipqs_configured=st.settings.ipqs_key != "",
                  remaining_today=remaining_today, daily_cap=st.settings.ipqs_daily_cap,
                  credits=credits, cost=min(len(view["ipqs_pending"]), remaining_today))


async def _ipqs_account(st: Any) -> dict[str, Any] | None:
    cache = st.ipqs_account_cache
    if cache and cache[0] > time.monotonic() - ACCOUNT_CACHE_SECONDS:
        return cache[1]
    body = await st.ipqs.account() if st.ipqs.configured else None
    st.ipqs_account_cache = (time.monotonic(), body)
    return body


@router.post("/accounts/{uuid}/ipqs")
async def account_ipqs(request: Request, uuid: str, force: str = Form("0")) -> Any:
    """The on-demand button: look up this account's distinct IPs (uncached ones, or all when
    re-checking), never past the day's remaining cap. Runs as a task; the page polls."""
    st = _state(request)
    uuid = uuid.lower()
    if not UUID_RE.match(uuid):
        return render(request, "error.html", message="Not a uuid.", status=404)
    if not st.ipqs.configured:
        return render(request, "error.html", message="IPQS_KEY is not set in .env.", status=400)
    existing = st.ipqs_runs.get(uuid)
    if existing and not existing.finished:
        return RedirectResponse(f"/accounts/{uuid}", status_code=303)
    ips = st.db.distinct_ips(uuid)
    cached = st.db.ipqs_rows(ips)
    targets = ips if force == "1" else [ip for ip in ips if ip not in cached]
    run = IpqsRun(uuid=uuid, total=len(targets))
    st.ipqs_runs[uuid] = run

    async def work() -> None:
        try:
            await _ipqs_account(st)   # credits shown on the page come from here, never from a render
            for ip in targets:
                # One lookup at a time across ALL accounts, and the day's remainder re-checked under
                # the lock each time: two accounts pressed together cannot overspend the cap.
                async with st.ipqs_lock:
                    if st.db.ipqs_spent_today() >= st.settings.ipqs_daily_cap:
                        run.capped = run.total - run.done
                        run.errors.append(f"daily cap of {st.settings.ipqs_daily_cap} reached — "
                                          f"{run.capped} IP(s) left for tomorrow")
                        break
                    ua, lang = ipqs_context(st.db, uuid, ip)
                    try:
                        body = await st.ipqs.lookup(ip, user_agent=ua, user_language=lang)
                        st.db.save_ipqs(ip, body)
                    except IPQSError as exc:
                        st.db.log_ipqs_failure(ip, str(exc), charged=exc.charged)
                        run.failed += 1
                        run.errors.append(f"{ip}: {exc}")
                        if "credit" in str(exc).lower() or "insufficient" in str(exc).lower():
                            run.errors.append("stopped: IPQS reports no credits")
                            break
                run.done += 1
        finally:
            run.finished = True
            st.ipqs_account_cache = None
            await _ipqs_account(st)

    run.task = asyncio.create_task(work())
    return RedirectResponse(f"/accounts/{uuid}", status_code=303)
