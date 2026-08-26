from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE0 = ROOT / "scripts" / "run_r002f_externally_pinned_stage0.ps1"
DOC = ROOT / "docs" / "R002F_EXTERNALLY_PINNED_STAGE0_AUTHORITY.md"
EXPECTED_GIT_BLOB = "4316675820ed937a4a04b9d99ea07619d0939757"
EXPECTED_SHA256 = "b2c15627e2264b950d0a64e8bb4224eb7540d13ef3f176237808b78a3af1a504"


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def test_exact_stage0_bytes_are_frozen() -> None:
    data = STAGE0.read_bytes()
    assert _git_blob_sha1(data) == EXPECTED_GIT_BLOB
    assert hashlib.sha256(data).hexdigest() == EXPECTED_SHA256


def test_python_is_isolated_and_does_not_write_bytecode() -> None:
    source = STAGE0.read_text(encoding="utf-8")
    assert "$python '-I' '-B' '-X' 'utf8'" in source
    assert "$env:PYTHONNOUSERSITE = '1'" in source


def test_git_optional_mutation_is_disabled() -> None:
    source = STAGE0.read_text(encoding="utf-8")
    assert "$env:GIT_NO_REPLACE_OBJECTS = '1'" in source
    assert "$env:GIT_OPTIONAL_LOCKS = '0'" in source
    assert "core.fsmonitor=false" in source
    assert "core.untrackedCache=false" in source


def test_stage0_pins_executable_and_tracked_files_without_delete_or_write_share() -> None:
    source = STAGE0.read_text(encoding="utf-8")
    assert "[System.IO.FileShare]::Read" in source
    assert "Stream-Sha256 $pythonStream" in source
    assert "Stream-Sha256 $gitStream" in source
    assert "Stream-GitBlobSha1 $stream" in source
    assert "tracked_files_pinned_against_write_delete = $true" in source


def test_cleanup_does_not_use_nonexistent_select_object_reverse_switch() -> None:
    source = STAGE0.read_text(encoding="utf-8")
    assert "Select-Object -Reverse" not in source
    assert "for ($index = $pins.Count - 1; $index -ge 0; $index--)" in source


def test_stage0_never_self_promotes_external_preexecution_authority() -> None:
    source = STAGE0.read_text(encoding="utf-8")
    assert "external_preexecution_pin_required = $true" in source
    assert "external_preexecution_pin_self_proven = $false" in source


def test_external_launcher_contract_keeps_stage0_handle_open_across_execution() -> None:
    doc = DOC.read_text(encoding="utf-8")
    assert EXPECTED_GIT_BLOB in doc
    assert EXPECTED_SHA256 in doc
    assert "FileShare]::Read" in doc
    assert "keep the stage-0 FileStream open" in doc
    assert "-NoProfile -NonInteractive" in doc
    assert "external_preexecution_pin_self_proven=false" in doc
