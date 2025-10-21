# Repository Guidelines

## Project Structure & Module Organization
- The repository currently only tracks `README.md`; treat new code contributions as greenfield and introduce structure deliberately.
- Place all runtime logic in `src/mini_cspm/`, keeping each scanner in `src/mini_cspm/scanners/` and shared utilities in `src/mini_cspm/common/`.
- Store reusable cloud or IaC fixtures under `assets/` and reference them from tests rather than inlining large payloads.
- Keep unit and integration tests in `tests/`, mirroring the `src/` layout (for example, `src/mini_cspm/scanners/k8s.py` maps to `tests/scanners/test_k8s.py`).
- When architecture notes or threat models are needed, add them under `docs/` and link from the README.

## Build, Test, and Development Commands
```bash
python3.11 -m venv .venv && source .venv/bin/activate  # set up local environment
pip install -r requirements.txt                         # install runtime + dev deps
make lint                                               # run Ruff + Black via Makefile target
make test                                               # run pytest with coverage gates
make run INPUT=examples/sample_state.json               # execute the CLI scanner against a fixture
```
Keep the Makefile targets thin wrappers around the underlying tools so CI can reuse them.

## Coding Style & Naming Conventions
- Format Python with Black (88 columns) and lint with Ruff; never commit unformatted code (`make lint --check` in CI).
- Use `snake_case` for functions and module names, `PascalCase` for classes, and `SCREAMING_SNAKE_CASE` for constants.
- Prefer pure functions inside scanners and isolate side effects (I/O, API calls) behind adapters in `src/mini_cspm/common/adapters.py`.
- Keep public functions documented with doctrings describing inputs, outputs, and failure modes.

## Testing Guidelines
- Write tests with `pytest`; name files `test_<module>.py` and functions `test_<behavior>()`.
- Ensure every scanner ships at least one fixture-driven test that validates severity calculation and resource targeting.
- Target ≥85% statement coverage; failing the `make test` coverage gate should block merging.
- For regression fixes, add a failing test before the fix and reference its name in the commit body.

## Commit & Pull Request Guidelines
- The existing history favors concise lowercase summaries (for example, `first commit`); continue using an imperative, ≤72-character subject (`scan: add kubernetes pod checks`).
- Include relevant scope tags (`feat`, `fix`, `chore`) when they clarify intent, and detail user-visible changes in the body.
- Every PR should describe the change, link related issues, enumerate tests executed, and attach CLI output or screenshots when behavior shifts.
- Request review once CI passes and assign the security lead for changes affecting policy severity or data flows.

## Security & Configuration Tips
- Never commit real cloud credentials; use `.env.example` to document required variables and load them via `src/mini_cspm/common/settings.py`.
- Keep dependency bumps small and run `pip-audit` (wired into `make lint`) before opening a PR.
- Document any new IAM permissions or external integrations in `docs/security.md` so reviewers can assess blast radius.
