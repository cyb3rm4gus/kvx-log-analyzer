-- Log Analyzer store. No PII: `player.email` / `player.phone` from Guardhouse are
-- discarded in the client before anything reaches this file (spec §4.2).
-- events / ips / uas are keyed by their own identity, not by batch, so the store
-- can later be queried across accounts (spec §4.1, owner ruling §1.3).
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS batches (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL,           -- running | done | failed
    uuid_count  INTEGER NOT NULL,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS batch_uuids (
    batch_id    TEXT NOT NULL REFERENCES batches(id) ON DELETE CASCADE,
    uuid        TEXT NOT NULL,
    -- queued | fetching | paused | done | no_events | unknown | failed
    status      TEXT NOT NULL DEFAULT 'queued',
    pages_done  INTEGER NOT NULL DEFAULT 0,
    has_more    INTEGER NOT NULL DEFAULT 1,
    events      INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    updated_at  TEXT,
    PRIMARY KEY (batch_id, uuid)
);

CREATE TABLE IF NOT EXISTS events (
    player_uuid           TEXT NOT NULL,
    created_at            TEXT NOT NULL,   -- UTC, as Guardhouse returns it
    frontend_session_uuid TEXT NOT NULL DEFAULT '',
    country               TEXT NOT NULL DEFAULT '',
    language              TEXT NOT NULL DEFAULT '',
    user_agent            TEXT NOT NULL DEFAULT '',
    click_id              TEXT NOT NULL DEFAULT '',
    url                   TEXT NOT NULL DEFAULT '',
    referrer_url          TEXT NOT NULL DEFAULT '',
    ip_address            TEXT NOT NULL DEFAULT '',
    -- All nine columns + uuid: collapses an exact repeat across a page boundary
    -- and nothing else (spec §2.2). NULLs are normalised to '' so the key holds.
    UNIQUE (player_uuid, created_at, frontend_session_uuid, country, language,
            user_agent, click_id, url, referrer_url, ip_address)
);
CREATE INDEX IF NOT EXISTS events_player_time ON events (player_uuid, created_at);
CREATE INDEX IF NOT EXISTS events_ip ON events (ip_address);
CREATE INDEX IF NOT EXISTS events_ua ON events (user_agent);

-- Automatic, keyless enrichment: RDAP network object + Team Cymru origin ASN.
CREATE TABLE IF NOT EXISTS ips (
    ip            TEXT PRIMARY KEY,
    rdap_registry TEXT,
    rdap_json     TEXT,
    net_name      TEXT,
    net_range     TEXT,
    net_type      TEXT,
    net_country   TEXT,
    registrant    TEXT,
    abuse_email   TEXT,
    asn           INTEGER,
    as_name       TEXT,
    prefix        TEXT,
    asn_registry  TEXT,
    error         TEXT,
    fetched_at    TEXT
);

-- Paid, on-demand enrichment (one credit per request, spec §3.3).
CREATE TABLE IF NOT EXISTS ipqs (
    ip              TEXT PRIMARY KEY,
    json            TEXT NOT NULL,
    fetched_at      TEXT NOT NULL,
    fraud_score     REAL,
    connection_type TEXT,
    isp             TEXT,
    organization    TEXT,
    asn             INTEGER,
    proxy           INTEGER,
    vpn             INTEGER,
    tor             INTEGER,
    active_vpn      INTEGER,
    active_tor      INTEGER,
    recent_abuse    INTEGER,
    bot_status      INTEGER,
    country_code    TEXT
);
-- A failed lookup is a fact too: shown on the page, retried on the next press.
CREATE TABLE IF NOT EXISTS ipqs_errors (
    ip           TEXT PRIMARY KEY,
    error        TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);
-- Every credit spent (requests IPQS actually processed), so the daily cap can be enforced.
CREATE TABLE IF NOT EXISTS ipqs_log (
    ip         TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    success    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ipqs_log_day ON ipqs_log (fetched_at);

CREATE TABLE IF NOT EXISTS uas (
    ua            TEXT PRIMARY KEY,
    browser       TEXT,
    browser_major TEXT,
    os            TEXT,
    os_version    TEXT,
    device        TEXT,
    parsed_at     TEXT
);

CREATE TABLE IF NOT EXISTS kv (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
