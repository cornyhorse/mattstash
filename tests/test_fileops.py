"""Unit tests for the private-file helpers used by backup and password rotation."""

import os
import stat
from pathlib import Path

import pytest

from mattstash.utils.fileops import copy_private, discard, stage_private_file


def mode(path: Path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_stage_private_file_is_0600_and_next_to_the_target(tmp_path: Path):
    target = tmp_path / "sidecar"
    old_umask = os.umask(0)
    try:
        staged = Path(stage_private_file(str(target), b"secret"))
    finally:
        os.umask(old_umask)
    assert staged.parent == tmp_path and staged != target and ".tmp-" in staged.name
    assert staged.read_bytes() == b"secret" and mode(staged) == 0o600
    assert not target.exists(), "staging does not publish"
    os.replace(staged, target)
    assert target.read_bytes() == b"secret" and mode(target) == 0o600


def test_stage_private_file_failure_leaves_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    def boom(fd):
        raise OSError("fsync failed")

    monkeypatch.setattr("mattstash.utils.fileops.os.fsync", boom)
    with pytest.raises(OSError, match="fsync failed"):
        stage_private_file(str(tmp_path / "sidecar"), b"x")
    assert list(tmp_path.iterdir()) == []


def test_discard_is_forgiving(tmp_path: Path):
    discard(None)
    discard(str(tmp_path / "never-existed"))
    present = tmp_path / "present"
    present.write_text("x")
    discard(str(present))
    assert not present.exists()


def test_copy_private_creates_a_private_complete_copy(tmp_path: Path):
    source = tmp_path / "src.bin"
    source.write_bytes(os.urandom(3 * 1024 * 1024 + 17))  # larger than one copy chunk
    source.chmod(0o644)
    dest = tmp_path / "dest.bin"
    copy_private(str(source), str(dest))
    assert dest.read_bytes() == source.read_bytes()
    assert mode(dest) == 0o600
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest.bin", "src.bin"]


def test_copy_private_never_overwrites_without_the_flag(tmp_path: Path):
    source = tmp_path / "src"
    source.write_text("new")
    dest = tmp_path / "dest"
    dest.write_text("old")
    with pytest.raises(FileExistsError):
        copy_private(str(source), str(dest))
    assert dest.read_text() == "old"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest", "src"]


def test_copy_private_refuses_to_follow_a_dangling_symlink(tmp_path: Path):
    source = tmp_path / "src"
    source.write_text("data")
    victim = tmp_path / "victim"
    link = tmp_path / "link"
    link.symlink_to(victim)
    with pytest.raises(FileExistsError):
        copy_private(str(source), str(link))
    assert not victim.exists(), "nothing is written through the symlink"


def test_copy_private_overwrite_replaces_atomically_and_fixes_the_mode(tmp_path: Path):
    source = tmp_path / "src"
    source.write_text("new")
    dest = tmp_path / "dest"
    dest.write_text("old")
    dest.chmod(0o666)
    copy_private(str(source), str(dest), overwrite=True)
    assert dest.read_text() == "new" and mode(dest) == 0o600


def test_copy_private_missing_source_leaves_nothing_behind(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        copy_private(str(tmp_path / "missing"), str(tmp_path / "dest"))
    assert list(tmp_path.iterdir()) == []
