-- AEGISINTEL schema v2: evidence provenance, assessment fields, behavioural indicators,
-- incident links and ATT&CK mapping review. Additive only: no data is dropped or rewritten.

-- Provenance: the timestamp exactly as received, and every normalisation decision made.
ALTER TABLE events ADD COLUMN original_timestamp TEXT;
ALTER TABLE events ADD COLUMN normalization_notes TEXT NOT NULL DEFAULT '[]';

-- Which version of a rule produced a finding (reproducibility).
ALTER TABLE findings ADD COLUMN rule_version TEXT NOT NULL DEFAULT '';

-- Assessment: severity = potential impact (existing column); confidence = strength of evidence;
-- detection_status = how the incident was found; disposition = the analyst's verdict.
ALTER TABLE incidents ADD COLUMN confidence TEXT NOT NULL DEFAULT 'medium'
    CHECK (confidence IN ('low', 'medium', 'high'));
ALTER TABLE incidents ADD COLUMN confidence_rationale TEXT NOT NULL DEFAULT '';
ALTER TABLE incidents ADD COLUMN detection_status TEXT NOT NULL DEFAULT 'known_detection'
    CHECK (detection_status IN ('known_detection', 'anomalous_behavior', 'suspicious_unmatched'));
ALTER TABLE incidents ADD COLUMN disposition TEXT NOT NULL DEFAULT 'undetermined'
    CHECK (disposition IN ('undetermined', 'true_positive', 'benign_confirmed', 'false_positive',
                           'inconclusive', 'insufficient_telemetry'));
ALTER TABLE incidents ADD COLUMN disposition_by INTEGER REFERENCES users(id);
ALTER TABLE incidents ADD COLUMN disposition_at TEXT;
ALTER TABLE incidents ADD COLUMN disposition_note TEXT;

-- ATT&CK mappings start as candidates; an analyst confirms or rejects them.
ALTER TABLE attack_mappings ADD COLUMN review_status TEXT NOT NULL DEFAULT 'candidate'
    CHECK (review_status IN ('candidate', 'confirmed', 'rejected'));
ALTER TABLE attack_mappings ADD COLUMN reviewed_by INTEGER REFERENCES users(id);
ALTER TABLE attack_mappings ADD COLUMN reviewed_at TEXT;

-- Statistical indicators are stored apart from rule findings: an anomaly score is not a
-- probability of compromise and is never presented as a rule match.
CREATE TABLE behavior_indicators (
    id               INTEGER PRIMARY KEY,
    detector_id      TEXT    NOT NULL,
    detector_version TEXT    NOT NULL,
    entity           TEXT    NOT NULL,
    score            REAL    NOT NULL CHECK (score >= 0 AND score <= 1),
    fingerprint      TEXT    NOT NULL,
    baseline         TEXT    NOT NULL,          -- JSON: what "normal" was, and how much of it
    rationale        TEXT    NOT NULL,
    observed_at      TEXT    NOT NULL,
    incident_id      INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL,
    UNIQUE (detector_id, fingerprint)
);
CREATE INDEX idx_behavior_incident ON behavior_indicators(incident_id);

CREATE TABLE behavior_indicator_events (
    indicator_id     INTEGER NOT NULL REFERENCES behavior_indicators(id) ON DELETE CASCADE,
    event_id         TEXT    NOT NULL REFERENCES events(id),
    PRIMARY KEY (indicator_id, event_id)
);

-- Possible relationships between incidents (shared entities, close in time). A link is a lead
-- for the analyst, not evidence of a common actor.
CREATE TABLE incident_links (
    incident_a       INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    incident_b       INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    shared_entities  TEXT    NOT NULL,          -- JSON list such as ["user:j.doe"]
    gap_minutes      INTEGER NOT NULL,
    rationale        TEXT    NOT NULL,
    created_at       TEXT    NOT NULL,
    PRIMARY KEY (incident_a, incident_b),
    CHECK (incident_a < incident_b)
);
CREATE INDEX idx_incident_links_b ON incident_links(incident_b);
CREATE INDEX idx_incidents_detection ON incidents(detection_status, disposition);
