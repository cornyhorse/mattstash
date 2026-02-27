"""
Pytest fixtures for CLI-Server integration tests.

These fixtures manage the Docker Compose lifecycle for the MattStash server.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Dict, Generator

import pytest
import httpx


@pytest.fixture(scope="session")
def docker_compose_file() -> Path:
    """Path to Docker Compose file."""
    return Path(__file__).parent.parent.parent / "server" / "docker-compose.yml"


@pytest.fixture(scope="session")
def server_url(docker_compose_file: Path) -> Generator[str, None, None]:
    """
    Start server via docker-compose and return URL.
    
    This is a session-scoped fixture so the server is started once for all tests.
    """
    # Check if Docker is available
    try:
        subprocess.run(
            ["docker", "--version"],
            check=True,
            capture_output=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("Docker not available")
    
    # Check if docker-compose is available
    try:
        subprocess.run(
            ["docker-compose", "--version"],
            check=True,
            capture_output=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        pytest.skip("docker-compose not available")
    
    # Start server
    print("\n🚀 Starting MattStash server via Docker Compose...")
    result = subprocess.run(
        ["docker-compose", "-f", str(docker_compose_file), "up", "-d"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        pytest.skip(f"Failed to start Docker Compose: {result.stderr}")
    
    # Wait for health check
    url = "http://localhost:8000"
    max_attempts = 30
    
    print(f"⏳ Waiting for server to be healthy at {url}...")
    for attempt in range(max_attempts):
        try:
            resp = httpx.get(f"{url}/api/health", timeout=2.0)
            if resp.status_code == 200:
                print(f"✓ Server is healthy after {attempt + 1} attempts")
                break
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        time.sleep(1)
    else:
        # Cleanup before failing
        subprocess.run(
            ["docker-compose", "-f", str(docker_compose_file), "down"],
            capture_output=True
        )
        pytest.fail(f"Server failed to start within {max_attempts} seconds")
    
    yield url
    
    # Teardown
    print("\n🛑 Stopping MattStash server...")
    subprocess.run(
        ["docker-compose", "-f", str(docker_compose_file), "down"],
        capture_output=True
    )


@pytest.fixture
def cli_env(server_url: str) -> Dict[str, str]:
    """
    Environment variables for CLI in server mode.
    
    Merges server configuration with current environment.
    """
    return {
        "MATTSTASH_SERVER_URL": server_url,
        "MATTSTASH_API_KEY": "test-api-key",  # From docker-compose
        **os.environ
    }


@pytest.fixture
def cli_env_invalid_key(server_url: str) -> Dict[str, str]:
    """Environment with invalid API key for testing authentication failures."""
    return {
        "MATTSTASH_SERVER_URL": server_url,
        "MATTSTASH_API_KEY": "invalid-key",
        **os.environ
    }


def run_cli(args: list, env: Dict[str, str]) -> subprocess.CompletedProcess:
    """
    Run mattstash CLI with given arguments and environment.
    
    Args:
        args: CLI arguments (e.g., ['get', 'my-secret'])
        env: Environment variables
        
    Returns:
        Completed process with stdout, stderr, and returncode
    """
    cmd = ["mattstash"] + args
    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True
    )


@pytest.fixture
def run_mattstash_cli():
    """Fixture that provides the run_cli function."""
    return run_cli
