"""``scripts/check-release.sh``: the check run before a release tag is created and again by the release workflow.

Each test builds a throwaway repository with a bare ``origin``, so nothing here touches the real repository.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-release.sh"
PYPROJECT = '[project]\nname = "demo"\nversion = "{version}"\n\n[tool.mypy]\npython_version = "3.11"\n'

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None, reason="needs git and bash"
)


def git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    done = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def commit(work: Path, name: str, version: str | None = None) -> None:
    if version is not None:
        (work / "pyproject.toml").write_text(PYPROJECT.format(version=version))
    (work / name).write_text(name)
    git(work, "add", "-A")
    git(work, "commit", "-q", "-m", name)


@pytest.fixture()
def work(tmp_path: Path) -> Path:
    origin = tmp_path / "origin.git"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True)
    clone = tmp_path / "work"
    subprocess.run(["git", "clone", "-q", str(origin), str(clone)], check=True, capture_output=True)
    git(clone, "checkout", "-q", "-b", "main")
    (clone / "scripts").mkdir()
    shutil.copy(SCRIPT, clone / "scripts" / "check-release.sh")
    commit(clone, "first", version="0.2.0")
    git(clone, "push", "-q", "origin", "main")
    return clone


def check(work: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(work / "scripts" / "check-release.sh"), *args],
        cwd=work,
        capture_output=True,
        text=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull},
    )


def fails_with(result: subprocess.CompletedProcess[str], pattern: str) -> bool:
    return result.returncode != 0 and re.search(pattern, result.stderr) is not None


def test_preflight_passes_on_the_tip_of_main_with_a_matching_version(work: Path):
    result = check(work, "v0.2.0", "--preflight")
    assert result.returncode == 0, result.stderr
    assert "can be created" in result.stdout


@pytest.mark.parametrize("tag", ["0.2.0", "v0.2", "v0.2.0.1", "v0.2.0-rc1", "release-1", ""])
def test_anything_but_vmajor_minor_patch_is_refused(work: Path, tag: str):
    assert check(work, tag, "--preflight").returncode != 0


def test_unknown_options_are_refused(work: Path):
    assert fails_with(check(work, "v0.2.0", "--force"), "unknown option")


def test_the_tag_must_match_the_version_in_pyproject(work: Path):
    assert fails_with(check(work, "v0.3.0", "--preflight"), r"says version 0\.2\.0 but the tag is v0\.3\.0")


def test_an_existing_local_tag_is_refused_in_preflight(work: Path):
    git(work, "tag", "v0.2.0")
    assert fails_with(check(work, "v0.2.0", "--preflight"), "already exists locally")


def test_a_tag_that_exists_only_on_origin_is_refused_in_preflight(work: Path):
    git(work, "tag", "v0.2.0")
    git(work, "push", "-q", "origin", "v0.2.0")
    git(work, "tag", "-d", "v0.2.0")
    assert fails_with(check(work, "v0.2.0", "--preflight"), "already exists on origin")


def test_preflight_requires_head_to_be_the_tip_of_origin_main(work: Path):
    commit(work, "second")
    git(work, "push", "-q", "origin", "main")
    git(work, "reset", "-q", "--hard", "HEAD~1")
    assert fails_with(check(work, "v0.2.0", "--preflight"), "not the tip of origin/main")


def test_a_commit_that_is_not_on_main_is_refused(work: Path):
    git(work, "checkout", "-q", "-b", "topic")
    commit(work, "topic-change", version="0.9.9")
    assert fails_with(check(work, "v0.9.9", "--preflight"), "not on origin/main")


def test_preflight_fails_when_origin_cannot_be_fetched(work: Path):
    git(work, "remote", "set-url", "origin", "/nonexistent/repo.git")
    assert fails_with(check(work, "v0.2.0", "--preflight"), "could not fetch origin/main")


def test_verify_passes_at_the_tag(work: Path):
    git(work, "tag", "v0.2.0")
    result = check(work, "v0.2.0")
    assert result.returncode == 0, result.stderr
    assert "matches pyproject.toml" in result.stdout


def test_verify_works_without_network_because_ci_has_already_fetched_main(work: Path):
    git(work, "tag", "v0.2.0")
    git(work, "remote", "set-url", "origin", "/nonexistent/repo.git")
    assert check(work, "v0.2.0").returncode == 0


def test_verify_needs_the_tag_to_exist(work: Path):
    assert fails_with(check(work, "v0.2.0"), "does not exist")


def test_verify_needs_the_tag_to_point_at_this_checkout(work: Path):
    git(work, "tag", "v0.2.0")
    commit(work, "second")
    git(work, "push", "-q", "origin", "main")
    assert fails_with(check(work, "v0.2.0"), "points at")


def test_verify_refuses_a_tag_on_a_commit_outside_main(work: Path):
    git(work, "checkout", "-q", "-b", "topic")
    commit(work, "topic-change", version="0.9.9")
    git(work, "tag", "v0.9.9")
    assert fails_with(check(work, "v0.9.9"), "not on origin/main")
