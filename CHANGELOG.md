# Changelog

All notable changes to AEGISINTEL are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-10-30
### Fixed
- Form fields (text inputs, text areas, number fields, dates, select boxes, multi-selects) now show an outline before they are clicked. The 1.0.0 styling targeted selectors that Streamlit 1.66 no longer renders. The fix was verified in a real browser.

### Added
- README screenshots captured from a running instance with synthetic sample data.

## [1.0.0] - 2026-10-30
First public release.

### Detection
- Three independent detection layers:
  - a Sigma-subset rule engine with versioned rules;
  - multi-event correlation (brute force, password spraying, follow-on success);
  - behavioural analytics: new logon network, rare process on a host, off-hours logon. These use past-only baselines and record coverage gaps.

### Investigation
- An incident model that keeps four things separate: **severity**, **confidence**, **detection status** and the analyst's **verdict**.
- Analysts can flag activity that no rule detected, and review ATT&CK mappings (candidate → confirmed or rejected).
- Related-incident links.
- Provenance on every event: the original timestamp and every normalisation decision.

### AI investigator
- Runs locally on Ollama. Its reports are checked against a fixed schema, cited evidence IDs are verified, and ATT&CK IDs are validated against the MITRE CTI dataset.
- Includes a prompt-injection scanner and a deterministic fallback for when the model is offline or its report fails checks.
- Similar-incident search on Chroma (optional).

### Response and security
- Response workflow: propose → two-person approval → **simulated** execution.
- Argon2id authentication with a terminal-issued admin setup code.
- Server-side sessions, role-based access control (RBAC) and a hash-chained audit log.

### Operations
- Verified backups with SHA-256 fingerprints, plus an automatic backup before every schema migration.
- Restore keeps an undo point. Admin recovery is terminal-only ("break-glass").
- Admin-only, audited deletion of imported data.

### Documentation
- `USER_MANUAL.txt` (end users), plus architecture, threat model, security and testing documents.
