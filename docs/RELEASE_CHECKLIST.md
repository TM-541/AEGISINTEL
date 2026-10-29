# Release checklist (public GitHub)

Tick each item before tagging a release from `develop` into `main`.
Record results in TESTING.md and the release notes in CHANGELOG.md.

## Repository content
- [ ] `git status` reviewed; **complete** staged diff read (`git diff --cached`)
- [ ] No `.env`, `data/`, `*.db`, `chroma/`, logs, `.venv/` or `attack_catalog.json` staged
      (`git add --dry-run .` and `git check-ignore -v data/ .env`)
- [ ] Secret scan of staged files is clean (keys, tokens, private keys, real passwords)
- [ ] Only synthetic data in `sample_data/` (RFC 5737 IPs, example.com, fictional users)
- [ ] No Trojan-Source characters (`pytest tests/test_repo_hygiene.py`)

## Quality gates
- [ ] `pytest` passes (record counts)
- [ ] `ruff check .` and `ruff format --check threatlens app.py scripts tests` pass
- [ ] `mypy threatlens app.py` passes
- [ ] `bandit -r threatlens scripts app.py -q` shows 0 open issues
- [ ] `pip_audit -r requirements.lock` reviewed; SECURITY.md advisory section up to date
- [ ] Optional live run: `pytest -m integration -s` with Ollama running

## Documentation
- [ ] README setup steps followed from a clean clone on Windows
- [ ] Screenshots in `docs/screenshots/` are real and current (or the README says none yet)
- [ ] TESTING.md numbers match the latest runs; nothing estimated
- [ ] Known limitations are current (README, SECURITY.md, THREAT_MODEL.md)
- [ ] LICENSE present and ATT&CK attribution retained

## Publishing (maintainer)
- [ ] CHANGELOG.md updated and `version` bumped in `pyproject.toml`
- [ ] Commits authored with the maintainer identity
- [ ] `develop` merged into `main`; annotated tag `vX.Y.Z` pushed; CI green on `main`
