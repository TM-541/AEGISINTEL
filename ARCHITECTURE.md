# AEGISINTEL — Architecture

## Overview

A **modular monolith**. One Python process hosts the Streamlit UI and an in-process service
layer. All security decisions live in the service layer, which is UI-agnostic. It could be
placed behind a FastAPI layer later without changing it.

```
                    ┌──────────────────────────────────────────────┐
  Browser ─(127.0.0.1)─▶  Streamlit UI  (threatlens/ui)              │
                    │     pages, components, theme                  │
                    │        │  passes only an opaque session token │
                    │        ▼                                      │
                    │  Service layer (threatlens/services)          │
                    │   auth · ingestion · correlation · detection  │
                    │   investigation · retrieval · response · audit│
                    │        │  every call: authorize(token, perm)  │
                    │        ▼                                      │
                    │  Security (threatlens/security)               │
                    │   passwords · authz/RBAC · validation · audit │
                    │        │                                      │
                    │        ▼                                      │
                    │  Repositories (threatlens/repositories)       │
                    │   parameterized SQL only, transactions        │
                    └────────┬──────────────────────┬───────────────┘
                             ▼                      ▼
                  SQLite (data/threatlens.db)   Integrations (threatlens/integrations)
                  versioned migrations           ├─ Ollama (httpx, loopback, timeouts)
                                                 ├─ Chroma (local persistent)
                                                 ├─ Sigma subset evaluator
                                                 └─ ATT&CK catalogue (validated IDs)
```

## Package layout and deviations

The requested top-level folders (`ui/`, `services/`, ...) live inside one importable package,
`threatlens/`. This avoids `sys.path` hacks, allows `pip install -e .`, and stops test
imports from shadowing each other. `app.py` stays at the root as the Streamlit entry point.

```
app.py                     Streamlit entry point
threatlens/
  config.py                typed, validated settings (env / .env)
  logging_setup.py         structured JSON logging with redaction
  errors.py                safe, user-facing error types
  timeutil.py              UTC helpers, defensive timestamp parsing
  db/                      connection factory + migrations/*.sql (checksummed)
  models/                  Pydantic domain models, enums, AI report schema
  repositories/            SQL access per aggregate (users, events, incidents, audit)
  security/                passwords (Argon2id), rbac (role → permission)
  ingest/                  parsers (JSON/JSONL/CSV), normalize, adapter protocol
  detection/               deterministic correlation rules
  services/                business logic: auth, users, ingestion, detection, incidents,
                           investigation (AI), retrieval, response, admin; container.py wires them
  integrations/            ollama (httpx), vector_store (Chroma), sigma (subset), attack
  ui/                      theme, components (escaping, guarded errors), nav, pages/ (12 views)
rules/sigma/               bundled Sigma-subset rules (YAML)
threatlens/integrations/data/attack_subset.json
sample_data/               synthetic datasets
scripts/                   init_db, fetch_attack, generate_samples, benchmark
tests/                     unit / integration / security tests
data/                      runtime DB + Chroma (git-ignored)
```

## Key decisions

### Persistence: stdlib `sqlite3` + numbered SQL migrations
- There is no ORM. Every query is parameterized and reviewable, which suits a security
  portfolio. Migrations are `NNNN_name.sql` files. A `schema_migrations` table records
  each one, and each runs inside a transaction.
- Each connection enables `PRAGMA foreign_keys=ON`, `journal_mode=WAL` and `busy_timeout`.
- **PostgreSQL path:** the repositories use a small SQL dialect. Moving to Postgres means
  `%s` placeholders, `TIMESTAMPTZ`, `JSONB` for raw events, row-level locking for the
  approval workflow, and a real migration tool (Alembic). SQLite is single-writer and is
  **not** suitable for concurrent multi-analyst enterprise load.

### Authentication with Streamlit
Streamlit offers OIDC (`st.login`) but no local password sessions, cookies or custom
response headers. AEGISINTEL therefore does the following:
- Argon2id password hashes (`argon2-cffi`, library defaults ≥ RFC 9106 low-memory profile).
- On login, the server creates a **random 256-bit session token**. Only its SHA-256 hash is
  stored in the `sessions` table, with absolute and idle expiry. The raw token sits only in
  Streamlit's server-side `st.session_state`. It is never placed in a URL or cookie.
- **Every** service call re-resolves token → session → user → role from the database.
  Disabled users, demoted users and expired sessions take effect on the next action.
- *Limitation:* a browser refresh starts a new Streamlit session, so the user must log in
  again. This is accepted as a safe default.
- *Limitation:* security headers (CSP, HSTS) cannot be set from Streamlit. For any non-local
  deployment, put a reverse proxy in front (see SECURITY.md).

### RBAC
Roles are `admin`, `analyst` and `viewer`, mapped to explicit `Permission` values in
`security/rbac.py`. Service methods declare the permission they require. The rules are:
- No self-role-change.
- Only an admin can create users or change roles.
- The last active admin cannot be disabled or demoted.

### Ingestion pipeline
`upload bytes → size/encoding/type checks → parser (JSON|JSONL|CSV) → per-record schema
validation → normalisation → content hash (SHA-256 of canonical JSON) → preview →
explicit confirm → single transaction insert (dedup via UNIQUE hash)`.
Raw records are kept as canonical JSON for provenance. Adapters (`IngestionAdapter`
protocol) allow future SIEM/EDR sources to plug in.

### Detection and correlation
- **Correlation rules** (Python, config-driven): for example *N failed logons for one user
  within W minutes followed by a success*. They are deterministic and produce
  `incidents` + `incident_events` links.
- **Sigma subset**: YAML rules are parsed with PyYAML and validated against a documented
  subset. That subset covers `selection` maps, the modifiers `contains|startswith|endswith|re|all`,
  lists as OR, and conditions built from `and/or/not`, `1 of x*` and `all of x*`. The
  `pySigma` package was considered. It parses rules but does not execute them against
  in-memory events, so we keep our own small, well-tested evaluator behind a
  `DetectionEngine` adapter. Unsupported constructs are **rejected**, not ignored.
- **ATT&CK**: a bundled curated catalogue of technique IDs, names and tactics with source URLs
  and dataset version. Every mapping is validated against it. Mappings carry
  `source=rule|ai`, a confidence level and evidence event IDs.

### AI investigation (Ollama)
- `httpx` calls `POST /api/chat` with `format=<JSON schema>`, `stream=false`, a timeout, and
  `num_predict` / `num_ctx` limits. Host and model come from configuration.
- Events go into the prompt inside a delimited **data block** as JSON. Each one is
  truncated, there is a maximum count, and they are labelled as untrusted. The system
  prompt states that instructions inside the data must be ignored.
- **Code is the boundary, not the prompt.** Output is parsed into a Pydantic schema. Every
  `evidence_event_ids` entry must belong to the incident, and ATT&CK IDs must exist in the
  catalogue. There are bounded retries, and a deterministic fallback report is used when
  the model is down. The model has no tools.

### Vector retrieval (Chroma)
Used only for **"find similar past incidents"**, where semantic similarity beats SQL
filters. Embeddings come from Ollama `nomic-embed-text` (configurable) and are supplied by us
(`embedding_function=None`, so Chroma never downloads a model). Embedded text is a behavioural
summary (rule titles, techniques, event types, process basenames) with no usernames, IPs or
hostnames. The collection name encodes the embedding model, and its metadata records the
vector dimension, so mismatches are refused. Cosine distance is set through the creation-time
`configuration` (Chroma 1.x rejects `hnsw:*` keys in mutable metadata). Chroma returns IDs
only. Every result is re-loaded and re-authorized from SQLite, so a stale or injected vector
can never surface content. Analyst-note indexing was considered and deferred: notes are short
and few, and SQL `LIKE` serves them.

### Deviations from the original plan (recorded)
- `ingest/` and `detection/` became their own packages instead of living under `services/`.
  They are pure, side-effect-free logic and are easier to test in isolation.
- Third-party alerts on the same host within ±60 min of a Sigma cluster are attached to the
  host incident as **context evidence** (no finding, no severity effect). This was added when
  a test showed the injection-bearing EDR alert was otherwise orphaned.
- The default model is `llama3.2:3b`, not `qwen3:8b`. This was measured: on the CPU-only
  development machine only the 3B model finished within the timeout.

### Response workflow
`proposal (AI or analyst) → pending → approve/reject (analyst+, with reason) → simulated
execution`. Every action carries `SIMULATED` labelling. A state machine plus a conditional
`UPDATE ... WHERE status='pending'` prevents replay and double approval. All transitions
are audited.

## Phase 2 (AEGISINTEL): layered detection, assessment and operations

### Detection layers (all independent of the LLM)
| Layer | Module | Unit of evidence | Versioning |
|---|---|---|---|
| 1. Sigma subset | `integrations/sigma.py` | `findings` (engine `sigma`) | `<modified\|date>+sha256:<rule text>` |
| 2. Correlation | `detection/correlation.py` | `findings` (engine `correlation`) | `<logic>+cfg:<threshold hash>` |
| 3. Behavioural analytics | `detection/behavior.py` | `behavior_indicators` (separate table) | `BEHAVIOR_LOGIC_VERSION` |

Behavioural detectors compare an event with the **same entity's own past**:
- **BH-001:** a new /24 (IPv6 /64) logon network for a user, needing at least 5 prior successful logons.
- **BH-002:** a process seen at most once on a host with at least 12 process events.
- **BH-003:** a logon more than 2 h outside the user's prior UTC hours, needing at least 8 prior logons.

Each detector is a single O(n) pass per entity; an earlier O(n²) version was caught by
benchmarking and is now guarded by a regression test. With too little history, a detector
records a **coverage gap** and does not invent a baseline. Scores in 0..1 express anomaly
strength, never a probability of compromise. Indicators are stored apart from rule findings
so the two can never be confused.

### Incident assessment (`detection/assessment.py`, pure functions)
- **Severity:** potential impact, from rules. Anomaly-only incidents are low or medium. Anomalies attached to rule incidents never raise severity.
- **Confidence:**
  - *high*: at least 2 independent signal types (Sigma, correlation, behaviour), or at least 3 distinct rules
  - *medium*: at least 1 rule
  - *low*: behaviour only, or an analyst flag

  It is recomputed on every detection run, with a stored plain-English rationale.
- **Detection status:** `known_detection`, `anomalous_behavior` or `suspicious_unmatched` (raised by an analyst).
- **Disposition:** set only by a human, with a mandatory justification. It is never touched by detection reruns.

Behavioural indicators attach to an incident that already holds their evidence, otherwise to
an incident sharing their entity within ±60 min, otherwise to a new "Anomalous behaviour"
incident. **Incident links** pair incidents that share a user, host or IP within 2 h. They
are presented as leads, never as evidence of a common actor.

### Schema v2 (`0002_assessment_provenance_behavior.sql`, additive only)
- `events.original_timestamp`, `events.normalization_notes`
- `findings.rule_version`
- `incidents.{confidence, confidence_rationale, detection_status, disposition, disposition_by/at/note}`
- `attack_mappings.{review_status, reviewed_by, reviewed_at}`
- tables `behavior_indicators`, `behavior_indicator_events`, `incident_links`

`Database.migrate()` takes a **verified backup before applying any migration to an existing
database**.

### Operations (`threatlens/maintenance.py`, terminal only)
- **Online backup** uses SQLite's backup API, which is consistent while running. Each backup is integrity-checked, gets a `.sha256` fingerprint, and never overwrites an existing file.
- **Restore** verifies the backup and its fingerprint, then saves the current DB as `pre-restore` before replacing it.
- **Break-glass admin recovery** works only for existing admin accounts. The password is typed at a hidden prompt; recovery revokes sessions, clears throttling and is audited.
- **Audited, admin-only purge** of an import removes its events, the incidents built on them, and orphaned findings and indicators. The audit trail records counts only.

### Branding
User-facing branding is defined once in `threatlens/branding.py` (name, tagline, logo).
Internal identifiers keep the original `threatlens` name for compatibility.
