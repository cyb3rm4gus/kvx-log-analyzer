# Log Analyzer

Paste a list of platform uuids, press **Process uuids**, and open a per-account page: every
event Guardhouse has for that account on a timeline (newest first, UTC), with markers where the
IP or the User-Agent changed, who holds each IP range (RDAP), its origin ASN (Team Cymru), and —
only when you press the button — IPQS reputation and connection type.

Spec and rulings: `obsidian/wiki/loganalyzer/loganalyzer_spec-how-to-build-2026-09-02.md`.

## Run

    cp .env.example .env      # fill in GH_TOKEN and IPQS_KEY
    ./run.sh                  # builds, starts on http://127.0.0.1:8090, checks Guardhouse readyz

Your machine must already be on the VPN that reaches Guardhouse (`GH_API_URL`); the launcher
only reports whether the container can see it.

## What is stored

A SQLite file in the `loganalyzer_data` volume: events (the nine warehouse columns per event),
distinct IPs with their RDAP/ASN/IPQS results and fetched-at stamps, parsed user agents, and
batch bookkeeping. **No email or phone** — Guardhouse returns them with every page and the
client discards them before anything is written (`guardhouse.py: strip_pii`, guarded again in
`db.py`). *Purge batch* removes a batch and the events of accounts no other batch references.

## Limits you will notice

- **Page-boundary caveat** on accounts with more than 1 000 events: Guardhouse's paging has no
  unique tiebreaker (scale-audit finding H3, unfixed by owner decision), so a row at a page
  boundary may be missing or doubled. The page says so.
- **IPQS** costs one credit per lookup; the button shows the cost and stops at 250/day.
- The automatic RDAP pass runs at one request per second per registry, after the events are in.

## Develop

    pip install -e .[dev]     # or the pinned runtime set: requirements.txt
    python3 -m pytest -q      # 58 tests, no network
    python3 scripts/loadtest.py uuids.txt   # the 100-uuid live test against Guardhouse (VPN up)
    python3 scripts/gen_requirements.py   # re-pin the hashed runtime requirements
