from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

import hms_gpt_vps.r002f_reviewed_git_tree_authority as authority
from hms_gpt_vps.r002f_reviewed_git_tree_authority import (
    R002FReviewedGitTreeAuthorityError,
    verify_project_manifest_against_reviewed_git_tree,
)
from hms_gpt_vps.r002f_sealed_execution_manifest import (
    SealedExecutionFile,
    SealedExecutionTreeManifest,
    TREE_ROLE_REVIEWED_PROJECT,
)


COMMIT = "a" * 40
GIT_SHA = "b" * 64
BLOB = "c" * 40


def _manifest(blob: str = BLOB) -> SealedExecutionTreeManifest:
    return SealedExecutionTreeManifest(
        reviewed_commit=COMMIT,
        tree_role=TREE_ROLE_REVIEWED_PROJECT,
        file_count=1,
        directory_count=0,
        total_size=1,
        files=(
            SealedExecutionFile(
                path="x.txt",
                size=1,
                sha256="d" * 64,
                git_blob_sha1=blob,
            ),
        ),
    )


def test_parse_ls_tree_accepts_regular_blob_modes_and_utf8_paths():
    raw = (
        b"100644 blob " + BLOB.encode("ascii") + b"\tx.txt\x00"
        b"100755 blob " + ("e" * 40).encode("ascii") + b"\tscripts/run.py\x00"
    )
    parsed = authority._parse_ls_tree_z(raw)
    assert parsed == {"x.txt": BLOB, "scripts/run.py": "e" * 40}


def test_parse_ls_tree_rejects_symlink_and_gitlink_modes():
    symlink = b"120000 blob " + BLOB.encode("ascii") + b"\tx.txt\x00"
    with pytest.raises(R002FReviewedGitTreeAuthorityError, match="mode/object"):
        authority._parse_ls_tree_z(symlink)

    gitlink = b"160000 commit " + BLOB.encode("ascii") + b"\tsubmodule\x00"
    with pytest.raises(R002FReviewedGitTreeAuthorityError, match="mode/object"):
        authority._parse_ls_tree_z(gitlink)


def test_parse_ls_tree_rejects_case_collision_and_control_path():
    collision = (
        b"100644 blob " + BLOB.encode("ascii") + b"\tx.txt\x00"
        b"100644 blob " + ("e" * 40).encode("ascii") + b"\tX.TXT\x00"
    )
    with pytest.raises(R002FReviewedGitTreeAuthorityError, match="case-colliding"):
        authority._parse_ls_tree_z(collision)

    control = b"100644 blob " + BLOB.encode("ascii") + b"\tbad\nname.txt\x00"
    with pytest.raises(R002FReviewedGitTreeAuthorityError, match="control"):
        authority._parse_ls_tree_z(control)


def test_verify_rebinds_manifest_to_exact_tree_and_brackets_checkout(monkeypatch):
    calls = []

    def checkout(root, commit, **kwargs):
        calls.append(("checkout", str(root), commit, str(kwargs["git_executable"])))

    monkeypatch.setattr(
        authority,
        "_read_reviewed_git_tree",
        lambda *args, **kwargs: {"x.txt": BLOB},
    )
    verify_project_manifest_against_reviewed_git_tree(
        _manifest(),
        repo_root=Path(r"C:\repo"),
        expected_commit=COMMIT,
        git_executable=Path(r"C:\git\git.exe"),
        git_executable_sha256=GIT_SHA,
        environment={"GIT_DIR": r"C:\evil", "SAFE": "1"},
        checkout_validator=checkout,
    )
    assert len(calls) == 2
    assert calls[0][2] == COMMIT
    assert calls[1][2] == COMMIT


def test_verify_rejects_manifest_mapping_drift(monkeypatch):
    monkeypatch.setattr(
        authority,
        "_read_reviewed_git_tree",
        lambda *args, **kwargs: {"x.txt": "e" * 40},
    )
    with pytest.raises(R002FReviewedGitTreeAuthorityError, match="mapping differs"):
        verify_project_manifest_against_reviewed_git_tree(
            _manifest(),
            repo_root=Path(r"C:\repo"),
            expected_commit=COMMIT,
            git_executable=Path(r"C:\git\git.exe"),
            git_executable_sha256=GIT_SHA,
            environment={},
            checkout_validator=lambda *args, **kwargs: None,
        )


def test_git_tree_command_uses_pinned_absolute_git_and_sanitized_environment(monkeypatch):
    stable = []

    class FakePinned:
        executable_path = r"C:\git\git.exe"

        def assert_stable(self):
            stable.append(True)

    @contextmanager
    def pin(path, sha):
        assert str(path) == r"C:\git\git.exe"
        assert sha == GIT_SHA
        yield FakePinned()

    monkeypatch.setattr(authority, "pin_reviewed_git_executable", pin)
    captured = {}

    def runner(argv, **kwargs):
        captured["argv"] = argv
        captured["env"] = kwargs["env"]
        return SimpleNamespace(
            returncode=0,
            stdout=b"100644 blob " + BLOB.encode("ascii") + b"\tx.txt\x00",
        )

    result = authority._read_reviewed_git_tree(
        Path(r"C:\repo"),
        COMMIT,
        git_executable=Path(r"C:\git\git.exe"),
        git_executable_sha256=GIT_SHA,
        environment={"SAFE": "1", "GIT_DIR": r"C:\evil"},
        command_runner=runner,
    )
    assert result == {"x.txt": BLOB}
    assert captured["argv"][0] == r"C:\git\git.exe"
    assert captured["argv"][-5:] == ["ls-tree", "-r", "-z", "--full-tree", COMMIT]
    assert "GIT_DIR" not in captured["env"]
    assert stable == [True, True]


def test_git_tree_command_failure_is_fail_closed(monkeypatch):
    class FakePinned:
        executable_path = r"C:\git\git.exe"

        def assert_stable(self):
            pass

    @contextmanager
    def pin(path, sha):
        yield FakePinned()

    monkeypatch.setattr(authority, "pin_reviewed_git_executable", pin)

    with pytest.raises(R002FReviewedGitTreeAuthorityError, match="command failed"):
        authority._read_reviewed_git_tree(
            Path(r"C:\repo"),
            COMMIT,
            git_executable=Path(r"C:\git\git.exe"),
            git_executable_sha256=GIT_SHA,
            environment={},
            command_runner=lambda *args, **kwargs: SimpleNamespace(
                returncode=1,
                stdout=b"",
            ),
        )
