-- THREATLENS initial schema. Timestamps are ISO-8601 UTC strings.

CREATE TABLE users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 64),
    display_name    TEXT    NOT NULL DEFAULT '' CHECK (length(display_name) <= 128),
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active       INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    last_login_at   TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE sessions (
    token_hash      TEXT    PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at      TEXT    NOT NULL,
    last_seen_at    TEXT    NOT NULL,
    expires_at      TEXT    NOT NULL,
    revoked_at      TEXT
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE login_attempts (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL,
    success         INTEGER NOT NULL CHECK (success IN (0, 1)),
    created_at      TEXT    NOT NULL
);
CREATE INDEX idx_login_attempts_time ON login_attempts(created_at);

CREATE TABLE imports (
    id              INTEGER PRIMARY KEY,
    file_label      TEXT    NOT NULL CHECK (length(file_label) <= 255),
    file_format     TEXT    NOT NULL CHECK (file_format IN ('json', 'jsonl', 'csv')),
    source_type     TEXT    NOT NULL,
    file_sha256     TEXT    NOT NULL UNIQUE,
    record_count    INTEGER NOT NULL,
    inserted_count  INTEGER NOT NULL,
    duplicate_count INTEGER NOT NULL,
    rejected_count  INTEGER NOT NULL DEFAULT 0,
    imported_by     INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT    NOT NULL
);

CREATE TABLE events (
    id              TEXT    PRIMARY KEY,               -- deterministic: EVT-<hash prefix>
    content_hash    TEXT    NOT NULL UNIQUE,
    import_id       INTEGER NOT NULL REFERENCES imports(id),
    source_type     TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    category        TEXT    NOT NULL,
    severity        TEXT    NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
    outcome         TEXT,
    username        TEXT,
    host            TEXT,
    src_ip          TEXT,
    dest_ip         TEXT,
    process_name    TEXT,
    command_line    TEXT,
    parent_process  TEXT,
    message         TEXT,
    raw_json        TEXT    NOT NULL,
    ingested_at     TEXT    NOT NULL
);
CREATE INDEX idx_events_time ON events(timestamp);
CREATE INDEX idx_events_user_time ON events(username, timestamp);
CREATE INDEX idx_events_host_time ON events(host, timestamp);
CREATE INDEX idx_events_type ON events(event_type);
CREATE INDEX idx_events_import ON events(import_id);

CREATE TABLE incidents (
    id              INTEGER PRIMARY KEY,
    title           TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
    status          TEXT    NOT NULL DEFAULT 'new'
                    CHECK (status IN ('new','triage','investigating','contained','resolved','false_positive')),
    assigned_to     INTEGER REFERENCES users(id),
    correlation_key TEXT    NOT NULL UNIQUE,
    rule_id         TEXT    NOT NULL,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
CREATE INDEX idx_incidents_status ON incidents(status, severity);

CREATE TABLE incident_events (
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id        TEXT    NOT NULL REFERENCES events(id),
    PRIMARY KEY (incident_id, event_id)
);
CREATE INDEX idx_incident_events_event ON incident_events(event_id);

CREATE TABLE findings (
    id              INTEGER PRIMARY KEY,
    rule_id         TEXT    NOT NULL,
    rule_title      TEXT    NOT NULL,
    engine          TEXT    NOT NULL CHECK (engine IN ('sigma', 'correlation')),
    severity        TEXT    NOT NULL CHECK (severity IN ('informational','low','medium','high','critical')),
    fingerprint     TEXT    NOT NULL,
    matched_fields  TEXT    NOT NULL,                  -- JSON
    incident_id     INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_at      TEXT    NOT NULL,
    UNIQUE (rule_id, fingerprint)
);
CREATE INDEX idx_findings_incident ON findings(incident_id);

CREATE TABLE finding_events (
    finding_id      INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    event_id        TEXT    NOT NULL REFERENCES events(id),
    PRIMARY KEY (finding_id, event_id)
);

CREATE TABLE attack_mappings (
    id              INTEGER PRIMARY KEY,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    finding_id      INTEGER REFERENCES findings(id) ON DELETE CASCADE,
    technique_id    TEXT    NOT NULL,
    source          TEXT    NOT NULL CHECK (source IN ('rule', 'ai')),
    confidence      TEXT    NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    rationale       TEXT    NOT NULL,
    evidence_ids    TEXT    NOT NULL,                  -- JSON array of event ids
    dataset_version TEXT    NOT NULL,
    created_at      TEXT    NOT NULL,
    UNIQUE (incident_id, technique_id, source, finding_id)
);

CREATE TABLE investigation_reports (
    id              INTEGER PRIMARY KEY,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    status          TEXT    NOT NULL CHECK (status IN ('validated', 'fallback')),
    model           TEXT    NOT NULL,
    report_json     TEXT    NOT NULL,
    validation_notes TEXT   NOT NULL DEFAULT '[]',
    duration_ms     INTEGER NOT NULL,
    attempts        INTEGER NOT NULL,
    created_by      INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT    NOT NULL
);
CREATE INDEX idx_reports_incident ON investigation_reports(incident_id, created_at);

CREATE TABLE incident_notes (
    id              INTEGER PRIMARY KEY,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author_id       INTEGER NOT NULL REFERENCES users(id),
    body            TEXT    NOT NULL CHECK (length(body) BETWEEN 1 AND 4000),
    created_at      TEXT    NOT NULL
);

CREATE TABLE response_proposals (
    id              INTEGER PRIMARY KEY,
    incident_id     INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type     TEXT    NOT NULL,
    target          TEXT    NOT NULL DEFAULT '',
    rationale       TEXT    NOT NULL,
    source          TEXT    NOT NULL CHECK (source IN ('ai', 'analyst')),
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'rejected', 'executed', 'failed')),
    proposed_by     INTEGER NOT NULL REFERENCES users(id),
    decided_by      INTEGER REFERENCES users(id),
    decided_at      TEXT,
    decision_reason TEXT,
    executed_at     TEXT,
    result_json     TEXT,
    idempotency_key TEXT    NOT NULL UNIQUE,
    created_at      TEXT    NOT NULL
);
CREATE INDEX idx_proposals_status ON response_proposals(status);

CREATE TABLE audit_events (
    id              INTEGER PRIMARY KEY,
    ts              TEXT    NOT NULL,
    actor_id        INTEGER,
    actor_username  TEXT,
    action          TEXT    NOT NULL,
    target_type     TEXT,
    target_id       TEXT,
    outcome         TEXT    NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
    details         TEXT    NOT NULL DEFAULT '{}',
    prev_hash       TEXT    NOT NULL,
    row_hash        TEXT    NOT NULL UNIQUE
);
CREATE INDEX idx_audit_ts ON audit_events(ts);
CREATE INDEX idx_audit_action ON audit_events(action);

-- Audit rows are append-only at the database level as well.
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;

CREATE TABLE app_config (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
