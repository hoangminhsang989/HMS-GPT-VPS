from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.qualification_file_authority import (
    read_file_pinned,
    require_existing_directory,
    require_new_file_target,
    write_json_create_only,
)


def test_pinned_read_round_trip_and_bound(tmp_path: Path) -> None:
    path = tmp_path / "proof.json"
    path.write_bytes(b'{"ok":true}\n')
    assert read_file_pinned(path, max_bytes=64, label="proof") == b'{"ok":true}\n'
    with pytest.raises(ValueError, match="size bound"):
        read_file_pinned(path, max_bytes=4, label="proof")


def test_pinned_read_rejects_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_bytes(b"")
    with pytest.raises(ValueError, match="must not be empty"):
        read_file_pinned(path, max_bytes=64, label="proof")


def test_create_only_json_publication_is_canonical_and_non_replacing(
    tmp_path: Path,
) -> None:
    target = tmp_path / "proof.json"
    write_json_create_only(
        target,
        {"z": 2, "a": True},
        max_bytes=1024,
        label="proof",
    )
    assert target.read_bytes() == b'{"a":true,"z":2}\n'
    with pytest.raises(FileExistsError):
        write_json_create_only(
            target,
            {"a": False},
            max_bytes=1024,
            label="proof",
        )


def test_new_file_target_requires_existing_clean_parent(tmp_path: Path) -> None:
    missing_parent = tmp_path / "missing" / "proof.json"
    with pytest.raises(FileNotFoundError):
        require_new_file_target(missing_parent, label="proof")


def test_authority_rejects_symlinked_file_and_parent(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    source = real / "proof.json"
    source.write_text('{"ok":true}\n', encoding="utf-8")

    file_link = tmp_path / "proof-link.json"
    parent_link = tmp_path / "parent-link"
    try:
        file_link.symlink_to(source)
        parent_link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating symlinks")

    with pytest.raises(PermissionError, match="link or reparse"):
        read_file_pinned(file_link, max_bytes=1024, label="proof")
    with pytest.raises(PermissionError, match="link or reparse"):
        read_file_pinned(parent_link / "proof.json", max_bytes=1024, label="proof")
    with pytest.raises(PermissionError, match="link or reparse"):
        require_existing_directory(parent_link, label="package")
    with pytest.raises(PermissionError, match="link or reparse"):
        require_new_file_target(parent_link / "new.json", label="proof")


def test_json_publication_rejects_nonfinite_payload(tmp_path: Path) -> None:
    target = tmp_path / "proof.json"
    with pytest.raises(ValueError):
        write_json_create_only(
            target,
            {"bad": float("nan")},
            max_bytes=1024,
            label="proof",
        )
    assert not target.exists()
