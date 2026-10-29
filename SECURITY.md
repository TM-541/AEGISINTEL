# Security Policy

AEGISINTEL is a **portfolio and lab project**. It is designed to run locally on loopback with
synthetic data. It is not a hardened multi-tenant product. Please read the limitations below
before using it with real data.

## Reporting a vulnerability
Please do not open a public issue. Report it privately through GitHub's
**Security -> Report a vulnerability** form on this repository (or contact the maintainer,
[@TM-541](https://github.com/TM-541)), with steps to reproduce and the affected version or
commit. Use synthetic data only; never send real logs or credentials. You should get an
acknowledgement within 7 days.

## Security design summary
| Control | Implementation |
|---|---|
| Passwords | Argon2id (argon2-cffi defaults), transparent rehash on login, 12–128 char policy |
| First admin | Only possible while zero users exist. Needs a one-time code from `scripts/init_db.py` (hashed, 30-min expiry, single use) |
| Sessions | 256-bit random token held server-side in Streamlit session state. Only the SHA-256 is stored. Idle + absolute expiry. Revoked on logout, password change, role change and disable |
| Authorization | RBAC (admin / analyst / viewer) enforced in the **service layer** on every call. Roles are re-read from the DB each time. No self role change. Last-admin protection |
| Brute force | Per-username throttling (applies even to unknown users) plus a global failure ceiling. Generic error messages |
| Audit | Append-only (SQLite triggers), SHA-256 hash-chained, verifiable from the UI. Sensitive keys redacted |
| Ingestion | Extension allow-list, size/record/field/nesting caps, strict UTF-8, in-memory only, sanitized labels, preview → hash-bound confirmation |
| SQL | Parameterized queries only. Dynamic SQL fragments come only from allow-lists |
| AI | Untrusted-data framing with nonce delimiters, JSON-schema output, code validation of evidence IDs and ATT&CK IDs, no tools, bounded retries/context/output, deterministic fallback, injection scanner |
| Response actions | Simulated only. Proposal → approval (two-person by default, reason + confirmation) → execution, atomic state transitions |
| Network | Streamlit bound to `127.0.0.1`. Ollama URL must be loopback unless explicitly overridden. XSRF protection on. Error details hidden from clients |

The full threat model is in [THREAT_MODEL.md](THREAT_MODEL.md).

## Known limitations (honest list)
- **No HTTP security headers.** Streamlit cannot set CSP/HSTS/X-Frame-Options. Put a reverse
  proxy (for example Caddy or nginx with TLS) in front of any non-loopback deployment.
- **Browser refresh logs you out.** Sessions live only in server-side Streamlit state. This is
  deliberate: there are no cookies to steal, at some cost in convenience.
- **Data at rest is not encrypted.** SQLite and Chroma files are protected only by OS
  permissions. Use full-disk encryption.
- **Audit-chain tampering is detected, not prevented.** Someone with write access to the DB
  file can rebuild the whole chain. Ship audit events to an external WORM store for real
  assurance.
- **Sigma regexes are trusted input.** Python `re` has no timeout. Only admins with
  filesystem access can add rules.
- **The LLM can still write misleading prose** that cites valid event IDs. Reports are
  labelled as AI hypotheses and need analyst review.
- **SQLite is single-writer** and not suited to concurrent multi-analyst enterprise use.

## Backup, recovery and data deletion
| Need | How | Safeguards |
|---|---|---|
| Backup | `scripts\backup_db.py` (also automatic before schema migrations) | Online-consistent, integrity-checked, `.sha256` fingerprint, never overwrites |
| Restore | `scripts\restore_db.py PATH` (app stopped) | Verifies the backup and its fingerprint; saves the current DB as `pre-restore` first; typed confirmation |
| Locked-out admin | `scripts\recover_admin.py USERNAME` | Terminal only (equivalent to file access); hidden prompt; existing admin accounts only; revokes sessions; audited |
| Delete imported data | Alerts & Events → Data retention (admins) | Impact preview, typed confirmation, atomic, audit records counts only |

Backups contain the same sensitive data as the live database. Store them with the same care.
The audit log is append-only and is not purged with imported data.

## Dependency advisories (recorded 2026-10-29)
`pip-audit` reports **5 advisories against `chromadb` 1.5.9** (GHSA-f4j7-r4q5-qw2c /
CVE-2026-45829, CVE-2026-45833, CVE-2026-45831, CVE-2026-45830). No fixed release was listed.
All five affect the **Chroma HTTP server** (`/api/v2/...` endpoints, server-side authorization
providers, and `trust_remote_code` model loading through the server API).

**Assessment:** AEGISINTEL uses only the embedded `PersistentClient` in-process. It runs no
Chroma server, opens no network listener, and sets `embedding_function=None` (embeddings come
from Ollama). The vulnerable code paths are not reachable in this deployment. **Do not** run
`chroma run` or expose a Chroma server alongside this project. Vector search is an optional
extra (`.[vector]`) and can be disabled with `THREATLENS_ENABLE_VECTOR_SEARCH=false`.
Re-check with `pip-audit -r requirements.lock` and upgrade when a fix is published.

## Detection limitations (phase 2)
- Behavioural baselines are learned from imported data and may include attacker activity.
  Detectors use past-only history and minimum-history thresholds but cannot tell "normal" from
  "attacker who was always there".
- BH-003 judges hours in UTC. Users in other time zones or on shifts will produce anomalies that
  are benign. That is why anomaly-only incidents are low confidence by design.
- Thresholds were tuned on synthetic data only (see TESTING.md). Real-world false-positive
  rates are unknown and must be evaluated on authorised, labelled data before relying on them.
