"""``s3-test`` keeps printing its endpoint line (to stderr) unless --quiet; library calls stay silent (L-6)."""

import subprocess
import sys
from pathlib import Path

import pytest
from dbhelpers import create_db

from mattstash import MattStash
from mattstash.cli.main import main

pytest.importorskip("boto3")

ENDPOINT_LINE = "[mattstash] Using endpoint=https://minio.local:9000, region=us-east-1, addressing=path"


@pytest.fixture(scope="module")
def db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return create_db(
        tmp_path_factory.mktemp("s3") / "s3.kdbx",
        [{"title": "minio", "username": "AKIAEXAMPLE", "password": "s3-secret-key", "url": "minio.local:9000"}],
    )


def test_cli_prints_the_endpoint_line_to_stderr(db: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["--db", str(db), "s3-test", "minio"]) == 0
    captured = capsys.readouterr()
    assert ENDPOINT_LINE in captured.err
    assert "Using endpoint" not in captured.out
    assert "s3-secret-key" not in captured.out + captured.err and "AKIAEXAMPLE" not in captured.out + captured.err


def test_cli_endpoint_line_reflects_the_options(db: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["--db", str(db), "s3-test", "minio", "--region", "eu-west-1", "--addressing", "virtual"]) == 0
    assert "region=eu-west-1, addressing=virtual" in capsys.readouterr().err


def test_cli_quiet_suppresses_everything(db: Path, capsys: pytest.CaptureFixture[str]):
    assert main(["--db", str(db), "s3-test", "minio", "--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_library_calls_are_silent_by_default(db: Path, capsys: pytest.CaptureFixture[str]):
    client = MattStash(path=str(db)).get_s3_client("minio")
    assert client is not None
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_library_verbose_goes_to_stderr_not_stdout(db: Path, capsys: pytest.CaptureFixture[str]):
    MattStash(path=str(db)).get_s3_client("minio", verbose=True)
    captured = capsys.readouterr()
    assert ENDPOINT_LINE in captured.err and captured.out == ""


def test_endpoint_line_is_on_stderr_in_a_real_process(db: Path):
    proc = subprocess.run(
        [sys.executable, "-m", "mattstash.cli.main", "--db", str(db), "s3-test", "minio"],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0
    assert ENDPOINT_LINE in proc.stderr
    assert "Using endpoint" not in proc.stdout
