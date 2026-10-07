# mattstash

A KeePass-backed secrets tool replacing credstash: a Python library and CLI (`src/mattstash`), a FastAPI server
(`server/app`) for docker-compose and Kubernetes, and docs (`docs/`, `server/docs/`). `docs/security-review.md` is the
decision record (findings, answers to design questions, open items); keep it current when behaviour changes.

## Commands

```bash
pip install -e ".[all,dev]"                                   # library + test tooling
pip install -r server/requirements.lock -r server/requirements-dev.txt   # server dependencies

pytest tests --ignore=tests/integration -n auto               # library suite (about 20 s)
pytest tests/integration -n auto                              # real CLI against a real server subprocess
(cd server && pytest)                                         # server suite

ruff check src tests server/app server/tests && ruff format --check src tests server/app server/tests
mypy src/mattstash --strict
```

CI (`.github/workflows/ci.yml`) runs lint, tests on Python 3.11-3.14, the server suite and an audit behind one `ci-gate`
job. Coverage of `src/mattstash` and `server/app` is 100%; CI fails below 99%. See `TESTING.md`.

## Things that have bitten us

- **Tests must pass as an unprivileged user and in a CI-like environment.** Running as root hides permission bugs, and
  GitHub runners set variables such as `USER`. A test that spawns a process and asserts on an environment variable must
  remove that variable from the inherited environment first.
- Tests use a deliberately cheap Argon2 setting (`tests/conftest.py`); tests about the real strength use the `real_kdf`
  marker. A test that creates a database in a subprocess must apply the same setting.
- Secret titles: `.` is the documented separator (`myapp.db-password`). `/` is also allowed in titles (library and CLI in
  local mode) but the server's URLs cannot address such names, so do not rely on them there.
- mypy is pinned in exactly one place, the `dev` extra in `pyproject.toml`.
- `.github/copilot-instructions.md` limits *Copilot* agents to a fixed list of markdown files. This file and
  `.claude/skills/` are intentional and are for Claude.

## Releases are manual

**Merging to `main` publishes nothing.** Release only when the user explicitly asks, and follow
`.claude/skills/release/SKILL.md`: version-bump PR, then a `vX.Y.Z` tag on the merge commit starts
`.github/workflows/release.yml` (PyPI, GitHub Release, GHCR image). Never push to `main`, move or delete a pushed tag,
publish by hand, or merge a release PR on your own.
