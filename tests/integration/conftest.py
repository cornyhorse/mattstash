"""
Pytest fixtures for CLI <-> server integration tests.

The real API server (``python -m app`` from ``server/``) runs as a subprocess on a free localhost port, backed by
a throw-away database, and the real ``mattstash`` CLI is run against it. No Docker is needed; the tests skip
only when the server's own dependencies (fastapi, uvicorn, slowapi) are not installed
(``pip install -r server/requirements.lock`` or ``-r server/requirements.in``).
"""

import importlib.util
import os
import shutil
import socket
import subprocess
import sys
import time
from collections.abc import Generator
from pathlib import Path
from typing import Dict

import httpx
import pytest

from mattstash import MattStash

SERVER_DIR = Path(__file__).resolve().parents[2] / "server"

#: >= the server's minimum key length (32); the value itself is arbitrary.
API_KEY = "integration-test-key-0123456789abcdef"
DB_PASSWORD = "integration-test-master-password"

_REQUIRED_MODULES = ("fastapi", "uvicorn", "slowapi")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _scrubbed_environment() -> Dict[str, str]:
    """The ambient environment without anything that would point the server or the CLI at a real vault."""
    return {k: v for k, v in os.environ.items() if not k.startswith(("MATTSTASH_", "KDBX_"))}


@pytest.fixture(scope="session")
def server_url(tmp_path_factory: pytest.TempPathFactory) -> Generator[str, None, None]:
    """Start the API server on a free port (read/write, one valid API key) and return its URL."""
    missing = [m for m in _REQUIRED_MODULES if importlib.util.find_spec(m) is None]
    if missing:
        pytest.skip(f"server dependencies not installed: {', '.join(missing)}")

    workdir = tmp_path_factory.mktemp("integration-server")
    db_path = workdir / "integration.kdbx"
    MattStash.create(str(db_path), password=DB_PASSWORD, sidecar=False)

    port = _free_port()
    url = f"http://127.0.0.1:{port}"
    env = {
        **_scrubbed_environment(),
        "MATTSTASH_DB_PATH": str(db_path),
        "KDBX_PASSWORD": DB_PASSWORD,
        "MATTSTASH_API_KEY": API_KEY,
        "MATTSTASH_ALLOW_WRITES": "true",
        "MATTSTASH_HOST": "127.0.0.1",
        "MATTSTASH_PORT": str(port),
        "MATTSTASH_LOG_LEVEL": "warning",
        # the tests make many requests (some deliberately with bad keys) from one address
        "MATTSTASH_RATE_LIMIT": "100000/minute",
        "MATTSTASH_AUTH_FAIL_LIMIT": "10000",
    }
    log_path = workdir / "server.log"
    with open(log_path, "wb") as log:
        process = subprocess.Popen(
            [sys.executable, "-m", "app"], cwd=SERVER_DIR, env=env, stdout=log, stderr=subprocess.STDOUT
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    pytest.fail(f"server exited with {process.returncode}:\n{log_path.read_text(errors='replace')}")
                try:
                    if httpx.get(f"{url}/health", timeout=1.0).status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                if time.monotonic() > deadline:
                    pytest.fail(f"server did not become healthy:\n{log_path.read_text(errors='replace')}")
                time.sleep(0.2)
            yield url
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover
                process.kill()
                process.wait()


@pytest.fixture
def cli_env(server_url: str) -> Dict[str, str]:
    """Environment for the CLI in server mode (never the developer's own vault)."""
    return {**_scrubbed_environment(), "MATTSTASH_SERVER_URL": server_url, "MATTSTASH_API_KEY": API_KEY}


@pytest.fixture
def cli_env_invalid_key(server_url: str) -> Dict[str, str]:
    """Environment with a wrong (but well-formed) API key for testing authentication failures."""
    return {
        **_scrubbed_environment(),
        "MATTSTASH_SERVER_URL": server_url,
        "MATTSTASH_API_KEY": "this-is-not-the-key-0123456789abcdef",
    }


def _cli_executable() -> str:
    """The ``mattstash`` console script of the interpreter running the tests (falls back to PATH)."""
    beside_python = Path(sys.executable).parent / "mattstash"
    return str(beside_python) if beside_python.exists() else (shutil.which("mattstash") or "mattstash")


def run_cli(args: list, env: Dict[str, str]) -> subprocess.CompletedProcess:
    """
    Run mattstash CLI with given arguments and environment.

    Args:
        args: CLI arguments (e.g., ['get', 'my-secret'])
        env: Environment variables

    Returns:
        Completed process with stdout, stderr, and returncode
    """
    return subprocess.run([_cli_executable(), *args], env=env, capture_output=True, text=True, timeout=60)


@pytest.fixture
def run_mattstash_cli():
    """Fixture that provides the run_cli function."""
    return run_cli
