# AEGISINTEL — Testing Record

All results below are from real runs on 2026-10-29 on the development machine:
Windows 11 Pro 10.0.26200, Intel 64-bit CPU (`Family 6 Model 165`), Python 3.11.9,
Ollama 0.40.11 (models running 100% on CPU). Nothing here is estimated.

## Test layout
| File | Focus |
|---|---|
| `tests/test_config_logging.py` | Config validation (loopback enforcement, ranges), log redaction, safe errors |
| `tests/test_persistence.py` | Migrations, checksum tamper detection, FKs/constraints, rollback, corrupt DB, audit chain |
| `tests/test_auth_security.py` | First-run setup, Argon2id, throttling, sessions, RBAC, escalation, audit of denials |
| `tests/test_ingestion.py` | Normalisation, hostile files (traversal, binary, NaN, deep nesting, oversize), dedup, provenance |
| `tests/test_detection.py` | ATT&CK validation and revocations, Sigma positive/negative cases, rule rejection, correlation thresholds, idempotency, incident state machine |
| `tests/test_investigation.py` | AI guardrails with a mocked Ollama: malformed output, invented/foreign IDs, schema abuse, unavailability, prompt injection, context bounds, rate limit |
| `tests/test_retrieval.py` | Chroma index: relevance, determinism, poisoned/stale vectors, PII exclusion, dimension mismatch, authz |
| `tests/test_response.py` | Approval workflow: two-person rule, replay, races, confirmation, AI-proposal provenance; audit/health |
| `tests/test_ui_smoke.py` | Headless Streamlit `AppTest`: all views render, backend denies viewers, overview numbers match DB, full setup→login flow |
| `tests/test_repo_hygiene.py` | Trojan-Source characters, `.gitignore` coverage |
| `tests/test_integration_live.py` | **Opt-in** (`-m integration`): real Ollama report + real embedding relevance |

## Results

### Unit / integration suite
```
> .venv\Scripts\python.exe -m pytest -p no:cacheprovider --cov=threatlens --cov-report=term
232 passed, 1 deselected in 1359.41s (0:22:39)
TOTAL  3178 statements, 366 missed, 88% line coverage
```
Without coverage the same suite takes ~80–95 s. (Coverage tracing slows the Argon2 and
Streamlit-heavy tests a lot.) The 1 deselected test is the opt-in live suite.
After this run, `test_live_embedding_retrieval_relevance` was added to the opt-in live file and
the default model/timeout changed. Later runs are recorded below.

Coverage by layer: models/security/repositories 90–100%; services 81–99%; UI pages 29–96%.
The lowest UI figures (`ai_report.py` 29%, `responses.py` 36%) are branches that only render
when reports or proposals exist. The smoke tests render those pages empty. Their logic is
covered at the service layer.

### Live integration (real Ollama, CPU-only)
| Test | Command | Result |
|---|---|---|
| AI report, `qwen3:8b` | `pytest tests/test_integration_live.py -m integration -s` | **Fallback**: model timed out at 600 s. The app degraded to the deterministic report as designed (test passed: the fallback path is valid) |
| AI report, `llama3.2:3b`, 15 events | same, with `THREATLENS_OLLAMA_MODEL=llama3.2:3b THREATLENS_AI_MAX_EVENTS=15` | **Validated on attempt 1** in 274.7 s; all cited IDs real; injection alert flagged; incident severity unchanged |
| Embedding relevance, `nomic-embed-text` | `pytest ... -m integration -k retrieval -s` | Brute-force incident → nearest: *Password spraying* (0.867) > *host activity* (0.691) |

Raw generation speed (single short prompt): `llama3.2:3b` 6.2 tok/s, `qwen3:8b` 4.0 tok/s, both
`100% CPU` per `ollama ps`.

### Static analysis and dependency audit
| Tool | Command | Result |
|---|---|---|
| Ruff lint | `ruff check .` | All checks passed |
| Ruff format | `ruff format --check threatlens app.py scripts` | 63 files already formatted |
| mypy (+ pydantic plugin) | `mypy threatlens app.py` | Success: no issues found in 60 source files |
| Bandit | `bandit -r threatlens scripts app.py` | 0 open issues (6,130 LOC). Reviewed sites carry `# nosec` with a written reason |
| pip-audit | `pip_audit -r requirements.lock` | **5 advisories in chromadb 1.5.9, no fix available**. Server-side only, not reachable here (SECURITY.md) |

Findings fixed because of these tools:
- **Bandit B613 (HIGH)**: literal bidirectional/zero-width characters in a regex source line
  (Trojan Source risk). Replaced with code-point construction. Regression test added.
- **mypy**: methods named `list` shadowed the builtin in class scope. Renamed to
  `list_incidents` / `list_proposals`. mypy then caught two UI call sites the rename had missed,
  which would have crashed at runtime.

### Runtime smoke
`streamlit run app.py --server.port 8599` → `/_stcore/health` returned `200 ok`, index page 200.
Streamlit log: `Uvicorn server started on 127.0.0.1:8599` (loopback only).

### Performance (`scripts/benchmark.py --scales 1 10 50`)
| scale | events | ingest (s) | events/s | detection (s) | incidents | findings | search p50 / p95 (ms) | list+detail all incidents p50 (ms) |
|---|---|---|---|---|---|---|---|---|
| x1 | 231 | 0.13 | 1,814 | 0.04 | 3 | 8 | 9.9 / 14.2 | 40.5 |
| x10 | 2,085 | 0.41 | 5,032 | 0.11 | 3 | 8 | 12.0 / 14.4 | 39.1 |
| x50 | 10,323 | 1.77 | 5,822 | 0.41 | 3 | 8 | 15.5 / 26.6 | 36.0 |

Search latency includes per-call session re-validation (one DB read plus one write). Incident
and finding counts stay constant as benign noise grows 50×, so this synthetic set produced no
added false positives. The benchmark excludes `alerts.csv`, hence 8 findings rather than 9.

## Not tested / limitations
- No real browser E2E (Playwright/Selenium). The UI is covered by Streamlit `AppTest` only, and
  CSS/visual rendering is unverified by automation.
- No load test with concurrent users. Concurrency is covered only by the 5-thread approval race.
- AI report *quality* is not scored. Only structural and evidence validity is checked.
- No testing on Linux or macOS, or on Python 3.12.
- Detection was evaluated only on synthetic data. Real-world precision and recall are unknown.
- ReDoS resistance of Sigma regexes is not bounded (rules are trusted input).

---

# Phase 2 (AEGISINTEL) — recorded results, 2026-10-30

### New test files
| File | Focus |
|---|---|
| `tests/test_maintenance.py` | Backup consistency and fingerprints, label path traversal, restore round trip and undo point, corrupt/foreign/tampered backups, automatic pre-migration backup, break-glass admin recovery |
| `tests/test_behavior_assessment.py` | BH-001/002/003 positive, negative, insufficient-baseline and past-only cases; confidence model; links; end-to-end layers on the sample scenario; idempotent reruns keep analyst verdicts; rule versions and provenance; analyst flagging, disposition, mapping review, AI-technique confirmation; AI context labelling; **linear-complexity regression** |
| `tests/test_import_hardening.py` | Import processing time limit, interrupted import atomicity, pagination counts, admin-only audited purge with FK integrity |
| `tests/test_ui_smoke.py` (extended) | Workspace and timeline render for all three detection statuses; AI report and approvals render with stored data; contrast test for the decorative background |

### Suite
```
> .venv\Scripts\python.exe -m pytest -p no:cacheprovider
288 passed, 2 deselected in 120.89s
```
Static checks on the same code: `ruff check .` (all passed) · `ruff format --check` (all
formatted) · `mypy threatlens app.py` (no issues, 64 files) · `bandit -r threatlens scripts
app.py` (0 open issues, 8,100 LOC). `pip-audit` was not re-run because the dependencies are
unchanged since 2026-10-29 (the same chromadb advisories apply).

### Behavioural analytics evaluation (synthetic, labelled by construction)
`scripts/generate_samples.py` plants 7 behaviourally anomalous events among 386 others (benign background plus attack activity that only the rule layers are expected to catch):
- j.doe's attacker logon (new network)
- 4 attack tools on ws-fin-07 (rare processes)
- a `certutil` download on ws-hr-02 (rare process, no Sigma rule)
- a 03:12 UTC logon by c.nguyen

| BH-003 hour tolerance | Indicators | True (planted) | False positives |
|---|---|---|---|
| 1 h | 9 | 7 | 2 (f.rossi 16:00, a.khan 17:00: normal hours missing from a 2-day baseline) |
| **2 h (default)** | **7** | **7** | **0** |

The encoded-PowerShell event is *not* flagged by BH-002, because PowerShell is common on that host.
It is covered by the Sigma layer, which is the intended division of labour between layers.
These figures come from synthetic data and do not predict real-world precision or recall.

### Performance (`scripts/benchmark.py --scales 1 10 50`, timings without tracing)
| scale | events | ingest (s) | events/s | detection, all layers (s) | incidents | findings | indicators | search p50 / p95 (ms) | list+detail p50 (ms) | peak heap (MB) |
|---|---|---|---|---|---|---|---|---|---|---|
| x1 | 393 | 0.18 | 2,155 | 0.05 | 5 | 8 | 7 | 7.5 / 9.0 | 44.7 | 1.7 |
| x10 | 3,687 | 0.64 | 5,742 | 0.20 | 5 | 8 | 7 | 14.0 / 18.0 | 43.9 | 16.6 |
| x50 | 18,312 | 3.58 | 5,117 | 0.92 | 5 | 8 | 7 | 14.8 / 17.9 | 45.4 | 82.0 |

**Regression found by measurement:** the first version of BH-001/BH-003 rebuilt each user's
history for every event (O(n²)). At x50, detection took **378.26 s**. Both detectors were
rewritten as single passes with identical output (verified indicator by indicator).
`test_logon_detectors_are_linear_not_quadratic` now counts work, so the regression cannot return
unnoticed. Peak heap is measured in a separate traced run, because tracing distorts timings.

### Upgrade of an existing database
`init_db.py` on an existing v1 database containing data applied migration 2 after an automatic pre-migration
backup, alongside an explicit backup taken earlier. Afterwards: schema `[1, 2]`, 1 user,
3 events, 1 incident preserved, `integrity_check = ok`, `foreign_key_check` empty.

### Live integration tests (real Ollama, CPU-only, opt-in)
```
> .venv\Scripts\python.exe -m pytest tests/test_integration_live.py -m integration -s
status: validated attempts: 1 ms: 320026
similar to brute force: [('Password spraying from a single source (203.0.113.45)', 0.8667),
                         ('Anomalous behaviour for user c.nguyen', 0.854)]
2 passed in 325.11s
```
- The AI report with `llama3.2:3b` passed schema and evidence validation on the first attempt and took 320 s (phase 1: 275 s).
- Similarity search ranks the related password-spraying incident first. However, an unrelated
  behaviour-only incident scores only 0.013 lower, so similarity scores from
  `nomic-embed-text` discriminate weakly on short incident summaries. Treat them as a
  ranking aid, not a measure of relatedness.

### Still not tested
- Real browser E2E. The UI is covered by Streamlit AppTest only.
- Behavioural detectors on real or authorised telemetry, so real false-positive rates are unknown.
- Concurrent multi-analyst load beyond the 5-thread approval race.
- Restore while the app is running. The manual requires stopping it, and nothing enforces that.

### Form-field visibility fix (2026-10-30)
Text inputs and text areas used the same colour as the panel around them, so they were
invisible until clicked. Fields now sit in a darker well (`#0A1120`) with an outline
(`#5A6C8A`) that has at least 3:1 contrast against both the panel and the field fill
(WCAG 1.4.11). The outline brightens on hover and shows an accent ring on focus.
`test_form_fields_are_visible_before_focus` checks these contrast ratios. Full suite:
**289 passed, 2 deselected**.

**Browser verification (v1.0.1):** the contrast test checked only the colour values. A real
headless-Chrome check found that the v1.0.0 CSS **did not apply**: Streamlit 1.66 renders inputs
with `stTextInputRootElement` / React Aria markup, not the BaseWeb selectors the CSS targeted.
The selectors were fixed for text inputs, text areas, number fields, dates, select boxes and
multi-selects. Computed styles were then confirmed in the browser: field background
`rgb(10,17,32)`, border `1px solid rgb(90,108,138)`. The README screenshots were taken after
this fix.
`test_field_selectors_exist_in_installed_streamlit_frontend` now fails if a Streamlit
upgrade renames any field the theme styles. Full suite: **290 passed, 2 deselected**.

### README screenshots (2026-10-30)
`docs/screenshots/*.png` were captured with headless Chrome (DevTools protocol) from a
throwaway instance with its own data directory, seeded only from `sample_data/`. The
owner's database was never used. The AI report screenshot shows a real `llama3.2:3b` run:
validated on attempt 1, 426 s on CPU. The demo instance and its data were deleted
afterwards.
