# AEGISINTEL — Threat Model

Method: a STRIDE-style review of the data flows in ARCHITECTURE.md. Scope: a local, single-host
deployment bound to loopback. Status values: **Implemented** (code plus a passing test,
named below), **Partial** (some aspects documented as limitations) and **Accepted**
(documented residual risk).

Last reviewed: 2026-10-29 (end of the initial build session).

## Assets
User credentials and sessions · imported telemetry (may contain usernames/hosts) ·
incidents, findings, reports · audit trail · approval decisions · configuration.

## Trust boundaries
1. Browser ↔ Streamlit server (loopback by default).
2. Uploaded file contents → parser (untrusted).
3. Stored event fields → LLM prompt (untrusted data crossing into an instruction channel).
4. LLM output → application (untrusted).
5. Application ↔ SQLite / Chroma files on disk.
6. Source tree / dependencies → runtime (supply chain).

## Threats and mitigations

| ID | Threat | Mitigation | Status · evidence |
|---|---|---|---|
| T1 | Credential stuffing / brute-force login | Argon2id; per-username throttle (also for unknown users); global failure ceiling; generic errors; audit | Implemented · `test_login_throttled_after_max_failures`, `test_unknown_user_throttled_identically`, `test_global_throttle`, `test_wrong_password_and_unknown_user_same_error` |
| T2 | Session hijack / fixation | 256-bit random token; only SHA-256 stored; new token per login; idle + absolute expiry; revoked on logout/password/role change/disable; never in URL or cookie | Implemented · `test_session_token_not_stored_in_plaintext`, `test_idle_expiry`, `test_absolute_expiry`, `test_logout_revokes_session`, `test_password_change_revokes_sessions` |
| T3 | Broken access control / privilege escalation | Permission check in the service layer on every call; role re-read from DB; no self role change or disable; last-admin protection; backend refuses admin pages for viewers even if the UI is bypassed | Implemented · `test_analyst_cannot_create_admin_or_self_promote`, `test_admin_cannot_change_own_role`, `test_role_change_takes_effect_immediately`, `test_admin_pages_refused_by_backend_for_viewer` |
| T4 | Unauthorized initial admin creation | Setup only while zero users; one-time code from a local terminal (hashed, 30-min TTL, single use); re-checked inside the write transaction | Implemented · `test_setup_requires_valid_code`, `test_expired_setup_code_rejected`, `test_setup_code_is_single_use`, `test_setup_closed_after_first_admin` |
| T5 | Malicious upload (oversize, binary, deep nesting, record flood) | Extension allow-list; byte cap before decode; strict UTF-8; NUL rejection; record/key/nesting caps; NaN/Infinity rejected; no archives | Implemented · `test_oversized_file_rejected_before_parsing`, `test_extremely_deep_json_does_not_crash`, `test_record_count_limit`, `test_malformed_files_rejected_with_safe_messages` |
| T6 | Path traversal | Uploads handled in memory; filename reduced to a sanitized display label; never used as a path | Implemented · `test_filename_sanitised_never_a_path` |
| T7 | Injection through event fields (SQL, HTML, CSV formula, terminal/bidi) | Parameterized SQL with allow-listed sort columns; HTML escaped in UI helpers; data shown via dataframes/code blocks; CSV export neutralises `= + - @`; control and bidi characters stripped at ingestion | Implemented · `test_search_is_injection_safe`, `test_sql_injection_payload_is_inert`, `test_control_and_bidi_characters_stripped_and_lengths_bounded` |
| T8 | Prompt injection (direct and indirect via logs) | Evidence JSON-encoded inside nonce-delimited untrusted block; system rules; **code-level** controls: schema, evidence-ID validation, ATT&CK validation, no tools, model cannot change state; deterministic injection scanner surfaces suspicious content | Implemented · `test_injection_in_alert_is_flagged_and_cannot_act`, `test_injection_payload_is_json_encoded_inside_data_block`, `test_prompt_marks_data_untrusted_and_excludes_raw_json` |
| T9 | Untrusted / hallucinated model output | Pydantic schema (`extra=forbid`, length caps); unknown or foreign event IDs reject the attempt; invalid/revoked technique IDs dropped with a note; timeline timestamps replaced with stored values; bounded retries; fallback report | Implemented · `test_invented_event_ids_rejected`, `test_event_ids_from_other_incidents_rejected`, `test_invalid_and_revoked_techniques_dropped_not_trusted`, `test_schema_forbids_unknown_actions_and_extra_fields`, `test_malformed_output_retries_then_falls_back` |
| T10 | Unsafe AI recommendations executed | Recommendations are inert data; analyst must promote one (validated reports only); a *different* analyst approves with reason + confirmation; atomic state machine; all actions simulated | Implemented · `test_ai_recommendation_becomes_proposal_only_on_request`, `test_proposer_cannot_self_approve`, `test_concurrent_approvals_only_one_wins`, `test_replay_and_double_decisions_rejected`, `test_tampered_report_action_is_revalidated` |
| T11 | Sensitive data exposure (errors, logs, UI, prompts) | `public_message` error model; `guarded()` UI wrapper shows a reference ID, never a trace; `client.showErrorDetails = "none"`; log redaction of password/token/secret keys; prompts not logged; secrets redacted from command lines before reaching the model; internal paths shown to admins only | Implemented · `test_errors_keep_detail_out_of_public_message`, `test_json_formatter_redacts_extras`, `test_password_never_in_audit_log`, `test_secrets_redacted`, `test_health_hides_internal_paths_from_non_admins`, `test_unavailable_model_falls_back_without_leaking` |
| T12 | Secrets mismanagement | No static secrets needed; `.env` git-ignored; `.env.example` placeholders only; typed validation at startup | Implemented · `test_out_of_range_values_fail_fast`, `test_no_runtime_data_or_env_tracked_by_gitignore` |
| T13 | DoS via large inputs or expensive model calls | Upload caps; batched inserts; model timeout, `num_predict`, bounded context; per-user hourly AI limit; no retry on transport failure | Implemented · `test_ai_rate_limit`, `test_context_is_bounded_and_truncated`, `test_unavailable_model_falls_back_without_leaking` |
| T14 | Database corruption / tampering | Transactions, FKs, CHECK/UNIQUE constraints; corrupt files fail safely; migration checksums detect edited migrations; integrity check on health page | Implemented · `test_corrupt_database_fails_safely`, `test_modified_migration_detected`, `test_foreign_keys_enforced`, `test_transaction_rolls_back_on_error` |
| T15 | Audit log tampering | Append-only triggers; SHA-256 hash chain verified in UI/health. *Detects* tampering; does not prevent a full-chain rewrite by someone with file access | Partial · `test_audit_chain_verifies_and_is_append_only`, `test_audit_chain_detects_tampering` |
| T16 | Supply chain | Pinned lock file; `pip-audit`; `bandit`; minimal deps; official MITRE data verified by source SHA-256. **Open:** 5 chromadb server-side advisories with no fix. Not reachable (embedded client only); see SECURITY.md | Partial · `pip-audit` run recorded in TESTING.md |
| T17 | Network exposure | Streamlit bound to `127.0.0.1`; Ollama host must be loopback unless explicitly overridden; URLs with credentials rejected; XSRF on | Implemented · `test_remote_ollama_rejected_without_opt_in`, `test_invalid_ollama_urls_rejected` |
| T18 | Vector store leakage / poisoning | Embedded text excludes usernames, IPs and hosts; Chroma returns IDs only; results re-loaded and re-authorized from SQLite; foreign/stale/malformed vector IDs discarded; viewers cannot search | Implemented · `test_foreign_and_stale_vectors_are_never_returned`, `test_documents_exclude_usernames_and_ips`, `test_viewer_cannot_search_or_reindex` |
| T19 | Trojan Source (bidi/invisible characters in source) | Repo-wide hygiene test; found and fixed a real instance during the build | Implemented · `test_no_trojan_source_characters` |
| T20 | Malicious detection rules | `yaml.safe_load`; strict subset with load-time rejection; regex length cap and pre-compilation; rules are admin-controlled files with no upload path | Partial · `test_yaml_with_python_tags_not_executed`, `test_unsupported_constructs_rejected` (ReDoS not bounded, see Accepted) |

## Accepted residual risks
- Anyone with OS-level access to the user account can read or modify the SQLite/Chroma files.
  At-rest encryption is out of scope; use full-disk encryption.
- Streamlit cannot emit CSP/HSTS headers. A reverse proxy is required for any non-loopback
  deployment.
- An LLM can still write misleading *prose* that cites valid event IDs. Reports are labelled
  AI hypotheses and require analyst review.
- Python `re` has no timeout, so a pathological regex in a Sigma rule could stall detection.
  Rules are trusted admin input.
- SQLite is single-writer, so concurrency is limited (see ARCHITECTURE.md → PostgreSQL path).

## Phase 2 additions (2026-10-30)

| ID | Threat | Mitigation | Status · evidence |
|---|---|---|---|
| T21 | **Missed detection** of activity no rule describes ("no alert = safe" fallacy) | Behavioural layer (BH-001/002/003); analyst flagging of unmatched activity; coverage gaps shown; UI and docs state that no detection is not proof of safety | Implemented · `test_unmatched_activity_is_surfaced_with_evidence`, `test_flag_events_creates_unmatched_incident`, `test_insufficient_baseline_reports_gap_not_indicator` |
| T22 | **Baseline poisoning / self-normalisation**: an event (or attacker history) makes itself look normal | Past-only baselines, so the event under evaluation is never in its own baseline; minimum-history thresholds; documented limitation that imported history may contain attacker activity | Partial · `test_baseline_is_past_only` (pre-existing attacker history is an accepted, documented risk) |
| T23 | **Misleading certainty**: anomaly scores read as probability of compromise; severity, confidence and verdict conflated | Separate fields; scores labelled "anomaly strength, not probability"; anomalies cannot raise rule severity; verdict human-only | Implemented · `test_anomalies_never_raise_rule_severity`, `test_scenario_layers_and_assessment`, `test_ai_context_includes_indicators_labelled_as_not_probability` |
| T24 | **Data loss / unsafe recovery** (failed migration, bad restore, locked-out admin) | Automatic pre-migration backup; verified backups with fingerprints; restore keeps a `pre-restore` undo point; terminal-only break-glass recovery, audited | Implemented · `test_pending_migration_on_existing_db_takes_backup_first`, `test_restore_round_trip_and_safety_copy`, `test_restore_detects_tampered_fingerprint`, `test_admin_recovery_resets_unlocks_and_audits` |
| T25 | **Unauthorised or careless deletion** of evidence | Admin-only purge; impact preview; typed file-name confirmation; dependent incidents removed atomically with FK integrity checked; audit records counts, not content | Implemented · `test_purge_shows_impact_then_deletes_import_and_dependent_incidents`, `test_only_admins_can_purge` |
| T26 | **Resource exhaustion** via slow imports or quadratic analytics | 60 s import processing limit; O(n) detectors with a deterministic complexity regression test; measured at 18k events | Implemented · `test_import_processing_time_limit`, `test_logon_detectors_are_linear_not_quadratic` |
| T27 | **Interrupted import** leaves partial or corrupt evidence | Single write transaction; rollback on failure; re-import succeeds | Implemented · `test_interrupted_import_leaves_no_partial_data` |
| T28 | **AI-suggested mappings** treated as fact | Mappings start as *candidate*; AI techniques become *confirmed* only through an analyst action that re-validates the technique ID and requires evidence from this incident | Implemented · `test_confirm_ai_technique_requires_validated_report_and_local_evidence`, `test_mapping_review_and_dashboard_excludes_rejected` |

Note on integrity: SHA-256 fingerprints on backups and the audit hash chain **detect** later
modification. They cannot prove that the original evidence was authentic when it was imported.
