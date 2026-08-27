from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from hms_gpt_vps.r002f_sealed_execution_acl import (
    build_exact_readonly_acl_powershell,
    validate_acl_evidence,
)
from hms_gpt_vps.r002f_sealed_execution_manifest import (
    R002FSealedExecutionTreeError,
    SealedExecutionTreeManifest,
    build_reviewed_project_manifest,
    verify_sealed_execution_tree,
)

COMMIT = "1" * 40


def git_blob(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def fixture_tree(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = tmp_path / "tree"
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "scripts").mkdir()
    files = {
        "src/pkg/__init__.py": b"x = 1\n",
        "src/pkg/empty.py": b"",
        "scripts/run.py": b"print('ok')\n",
    }
    for relative, data in files.items():
        (root / Path(*relative.split("/"))).write_bytes(data)
    return root, {path: git_blob(data) for path, data in files.items()}


def test_manifest_binds_external_git_tree_and_empty_file(tmp_path: Path) -> None:
    root, blobs = fixture_tree(tmp_path)
    manifest = build_reviewed_project_manifest(
        root, reviewed_commit=COMMIT, expected_git_blobs=blobs
    )
    assert manifest.file_count == 3
    assert manifest.directory_count == 3
    verify_sealed_execution_tree(root, manifest)
    decoded = SealedExecutionTreeManifest.from_bytes(manifest.to_bytes())
    assert decoded == manifest
    assert decoded.sha256 == hashlib.sha256(decoded.to_bytes()).hexdigest()


def test_external_blob_drift_is_rejected(tmp_path: Path) -> None:
    root, blobs = fixture_tree(tmp_path)
    blobs["scripts/run.py"] = "2" * 40
    with pytest.raises(R002FSealedExecutionTreeError):
        build_reviewed_project_manifest(root, reviewed_commit=COMMIT, expected_git_blobs=blobs)


def test_extra_file_and_empty_directory_are_rejected(tmp_path: Path) -> None:
    root, blobs = fixture_tree(tmp_path)
    manifest = build_reviewed_project_manifest(root, reviewed_commit=COMMIT, expected_git_blobs=blobs)
    (root / "src" / "pkg" / "evil.py").write_text("raise SystemExit\n", encoding="utf-8")
    with pytest.raises(R002FSealedExecutionTreeError):
        verify_sealed_execution_tree(root, manifest)
    (root / "src" / "pkg" / "evil.py").unlink()
    (root / "src" / "pkg" / "empty-dir").mkdir()
    with pytest.raises(R002FSealedExecutionTreeError):
        verify_sealed_execution_tree(root, manifest)


def test_case_collision_and_duplicate_json_are_rejected(tmp_path: Path) -> None:
    root, blobs = fixture_tree(tmp_path)
    blobs["SCRIPTS/RUN.PY"] = blobs["scripts/run.py"]
    with pytest.raises(R002FSealedExecutionTreeError):
        build_reviewed_project_manifest(root, reviewed_commit=COMMIT, expected_git_blobs=blobs)
    blobs.pop("SCRIPTS/RUN.PY")
    manifest = build_reviewed_project_manifest(root, reviewed_commit=COMMIT, expected_git_blobs=blobs)
    raw = manifest.to_bytes().decode("utf-8")
    malicious = raw.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
    with pytest.raises(R002FSealedExecutionTreeError):
        SealedExecutionTreeManifest.from_bytes(malicious.encode("utf-8"))


def test_acl_contract_is_protected_read_execute_only(tmp_path: Path) -> None:
    root, _ = fixture_tree(tmp_path)
    script = build_exact_readonly_acl_powershell(root, reconcile=False)
    assert "AreAccessRulesProtected" in script
    assert "ReadAndExecute" in script
    assert "FullControl" not in script
    assert "FileSystemRights]::Write" not in script
    assert "FileSystemRights]::Delete" not in script
    assert "rules.Count -ne 2" in script
    assert "Sort-Object { $_.Path.Length } -Descending" in script


def test_acl_evidence_is_type_exact(tmp_path: Path) -> None:
    root, _ = fixture_tree(tmp_path)
    evidence = {
        "ready": True,
        "changed": False,
        "root": str(root.absolute()),
        "entry_count": 6,
        "directory_acls_exact": True,
        "file_acls_exact": True,
        "reparse_point_found": False,
    }
    assert validate_acl_evidence(evidence, root=root, expected_entry_count=6, reconcile=False) == evidence
    bad = dict(evidence); bad["entry_count"] = True
    with pytest.raises(R002FSealedExecutionTreeError):
        validate_acl_evidence(bad, root=root, expected_entry_count=6, reconcile=False)
