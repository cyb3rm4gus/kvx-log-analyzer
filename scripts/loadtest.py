#!/usr/bin/env python3
"""The owner's load test (spec §7, ruling 2.3-a): 100 uuids against the REAL Guardhouse through a
running Log Analyzer. Run on the analyst's machine with the VPN up:

    python3 scripts/loadtest.py uuids.txt [http://127.0.0.1:8090]

While it runs, watch Guardhouse's memory on its host (`docker stats guardhouse`) — finding H2 means
a heavy account can push the 256 MiB container over its limit. Report: wall clock, per-uuid status,
pages, events, distinct IPs, and the enrichment time — the "distinct IPs per uuid" number the spec
still lacks. Needs only the standard library."""
from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request

def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__); return 2
    base = (sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:8090").rstrip("/")
    uuids = open(sys.argv[1]).read()
    n = len(re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uuids, re.I))
    print(f"posting {n} uuids to {base}")
    t0 = time.monotonic()
    req = urllib.request.Request(f"{base}/batches", data=urllib.parse.urlencode({"uuids": uuids}).encode(), method="POST")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k): return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(req)
    except urllib.error.HTTPError as e:
        if e.code != 303: raise
        batch = e.headers["Location"].split("/")[2].split("?")[0]
    print("batch", batch)
    with urllib.request.urlopen(f"{base}/batches/{batch}/events") as s:
        for line in s:
            line = line.decode().strip()
            if line.startswith("data:") and line != "data: {}":
                msg = json.loads(line[5:])["message"]
                print(f"{time.monotonic() - t0:8.1f}s  {msg}")
            elif line.startswith("event: end"):
                break
    print(f"total {time.monotonic() - t0:.1f}s — open {base}/batches/{batch} for per-uuid pages/events/IPs")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
