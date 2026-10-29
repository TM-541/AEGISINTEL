# Contributing to AEGISINTEL

AEGISINTEL is maintained by [@TM-541](https://github.com/TM-541). Issues and pull requests
are welcome. Every change is reviewed and merged by the maintainer.

## Branches
| Branch | Purpose |
|---|---|
| `main` | Released, tagged versions only (`vX.Y.Z`). Never commit directly. |
| `develop` | Integration branch. Pull requests target `develop`. |
| `feature/<name>`, `fix/<name>` | Short-lived work branches from `develop`. |

Releases follow [docs/RELEASE_CHECKLIST.md](docs/RELEASE_CHECKLIST.md): `develop` is merged into
`main`, tagged, and recorded in [CHANGELOG.md](CHANGELOG.md).
Commit messages use the [Conventional Commits](https://www.conventionalcommits.org/) style
(`feat:`, `fix:`, `docs:`, `test:`, `chore:`).

## Setup
```powershell
py -3.11 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.lock
.venv\Scripts\python.exe -m pip install -e . --no-deps
```
Regenerate the lock after changing dependencies:
`uv pip compile pyproject.toml --extra dev --extra vector --python-version 3.11 -o requirements.lock`.

## Before opening a pull request
```powershell
.venv\Scripts\python.exe -m ruff format threatlens app.py scripts tests
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m mypy threatlens app.py
.venv\Scripts\python.exe -m bandit -r threatlens scripts app.py -q
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m pip_audit -r requirements.lock
```
All of these should pass, except for the documented `chromadb` advisories (see SECURITY.md).

## Rules of the road
- **Layering:** UI → services → repositories. The UI never runs SQL or makes authorization
  decisions. Every public service method takes the session token and calls `authorize()`.
- **SQL:** parameters only (`?`). If you must build a clause dynamically, take it from an
  allow-list and add `# noqa: S608` / `# nosec B608` with a one-line justification.
- **Untrusted input:** treat imported events, filenames, rule text and model output as
  hostile. Validate in code, not in prompts.
- **AI output never changes state.** It can only be displayed, or promoted by a human into a
  proposal that a *different* human approves.
- **Response actions stay simulated.** Real integrations need a design review and explicit
  maintainer approval.
- **Tests:** every security control needs a negative test. Use `tmp_path` and mock Ollama with
  `httpx.MockTransport`. Live tests go behind `@pytest.mark.integration`.
- **Schema changes:** add a new `threatlens/db/migrations/NNNN_name.sql`. Never edit an
  applied migration. The runner detects checksum changes and refuses to start.
- **Honesty:** don't claim support you haven't tested (see `docs/SIGMA_SUBSET.md` for the
  standard we follow).
- **Source hygiene:** keep source ASCII-safe. `tests/test_repo_hygiene.py` rejects
  bidirectional or zero-width characters (Trojan Source).
