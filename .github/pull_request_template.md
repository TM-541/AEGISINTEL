## Summary
<!-- What changes and why. -->

## Checklist
- [ ] Targets `develop` (only release merges go to `main`)
- [ ] `ruff check .`, `ruff format --check`, `mypy`, `bandit`, `pytest` pass locally
- [ ] Security controls touched have negative tests
- [ ] `USER_MANUAL.txt` updated if UI labels or commands changed
- [ ] No secrets, `.env`, databases, real logs or customer data included
