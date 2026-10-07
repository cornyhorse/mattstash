# Running the tests

```bash
pip install -e ".[all,dev]"                       # library + test tooling (pytest, xdist, cov, ...)

pytest tests --ignore=tests/integration -n auto   # library suite, in parallel (about a minute on a laptop)
pytest tests/integration -n auto                  # real CLI against a real server subprocess (needs the server deps, below)

pip install -r server/requirements.lock           # server runtime dependencies (hash-pinned, as in the Docker image)
pip install -r server/requirements-dev.txt
(cd server && pytest)                             # server suite incl. the 90% coverage gate (about 20 s)

ruff check src tests server/app server/tests && ruff format --check src tests server/app server/tests
mypy src/mattstash --strict
```

`scripts/` has helpers for coverage runs. Nothing needs Docker: the integration tests start `python -m app` on a free
localhost port with a throw-away database, and skip themselves only when fastapi/uvicorn/slowapi are not installed.

## Why the suite is fast: a cheap KDF in tests

A KeePass database is encrypted with a key derived by Argon2 (64 MiB, 14 passes), which costs about half a second per
open and per save. Spending that thousands of times proves nothing, so `tests/conftest.py` (and
`server/tests/conftest.py`) point pykeepass at a copy of its blank-database template with a nearly free Argon2 setting.
Databases are created from that template and keep its parameters in their header, so subprocesses started by the tests
(a real server, the CLI) read them from the file and are fast too.

- Production code is untouched: `mattstash setup` / `MattStash.create` still produce the strong default.
- `tests/test_kdf_strength.py` asserts exactly that (marker `@pytest.mark.real_kdf` opts a test out of the cheap KDF),
  and that the cheap setting really is active in all other tests.
- A test that creates a database in a **subprocess** must apply the same setting; see `_CREATOR` in
  `tests/test_review_findings.py` (it reads `MATTSTASH_TEST_BLANK_DB`, which the session fixture sets).
- If a new test is unexpectedly slow, check that its database came from `MattStash.create` in the test process (or
  from the `temp_db` / `create_db` helpers) and not from a subprocess or a hand-built file with default parameters.
