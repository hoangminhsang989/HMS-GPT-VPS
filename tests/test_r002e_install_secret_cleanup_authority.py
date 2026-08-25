from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from hms_gpt_vps import install_artifacts as artifacts_module
from hms_gpt_vps.install_artifacts import clear_install_secrets


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = "protected-bootstrap"

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("missing")
        return self.value

    def clear(self) -> None:
        self.value = None


def _managed_answer(tmp_path: Path) -> tuple[Path, Path, bytes]:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    answer = runtime / "hms-answer.iso"
    payload = b"managed-answer-media"
    answer.write_bytes(payload)
    return runtime, answer, payload


def test_cleanup_requires_exact_managed_answer_name(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    other = runtime / "other.iso"
    payload = b"same-bytes"
    other.write_bytes(payload)
    store = MemorySecretStore()

    with pytest.raises(ValueError, match="exact managed runtime artifact"):
        clear_install_secrets(
            other,
            store,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            runtime_dir=runtime,
        )

    assert other.read_bytes() == payload
    assert store.load_text() == "protected-bootstrap"


@pytest.mark.parametrize("bad_hash", [None, True, 1, "", "0" * 63, "z" * 64])
def test_cleanup_rejects_non_exact_digest_type_or_shape(
    tmp_path: Path,
    bad_hash: object,
) -> None:
    runtime, answer, _ = _managed_answer(tmp_path)
    store = MemorySecretStore()
    with pytest.raises(ValueError, match="SHA-256"):
        clear_install_secrets(
            answer,
            store,
            expected_sha256=bad_hash,  # type: ignore[arg-type]
            runtime_dir=runtime,
        )
    assert answer.exists()
    assert store.load_text() == "protected-bootstrap"


def test_cleanup_rejects_redirected_answer_and_preserves_secret(tmp_path: Path) -> None:
    runtime, answer, payload = _managed_answer(tmp_path)
    answer.unlink()
    real = runtime / "real.iso"
    real.write_bytes(payload)
    managed = runtime / "hms-answer.iso"
    try:
        managed.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")

    store = MemorySecretStore()
    with pytest.raises(PermissionError, match="link or reparse"):
        clear_install_secrets(
            managed,
            store,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            runtime_dir=runtime,
        )
    assert real.exists()
    assert store.load_text() == "protected-bootstrap"


def test_cleanup_identity_failure_does_not_delete_or_clear_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, answer, payload = _managed_answer(tmp_path)
    store = MemorySecretStore()

    monkeypatch.setattr(
        artifacts_module,
        "_target_matches_identity",
        lambda *args, **kwargs: False,
    )
    with pytest.raises(RuntimeError, match="authority changed"):
        clear_install_secrets(
            answer,
            store,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            runtime_dir=runtime,
        )

    assert answer.read_bytes() == payload
    assert store.load_text() == "protected-bootstrap"


def test_cleanup_delete_failure_preserves_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, answer, payload = _managed_answer(tmp_path)
    store = MemorySecretStore()

    def _fail_delete(*args: object, **kwargs: object) -> None:
        raise RuntimeError("simulated exact delete failure")

    monkeypatch.setattr(artifacts_module, "_delete_verified_answer_iso", _fail_delete)
    with pytest.raises(RuntimeError, match="simulated exact delete failure"):
        clear_install_secrets(
            answer,
            store,
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            runtime_dir=runtime,
        )

    assert answer.exists()
    assert store.load_text() == "protected-bootstrap"


@pytest.mark.skipif(os.name != "nt", reason="Windows exact-handle deletion contract")
def test_windows_cleanup_does_not_use_pathname_unlink_after_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime, answer, payload = _managed_answer(tmp_path)
    store = MemorySecretStore()

    def _forbid_unlink(*args: object, **kwargs: object) -> None:
        raise AssertionError("Windows cleanup must delete the verified opened handle")

    monkeypatch.setattr(os, "unlink", _forbid_unlink)
    clear_install_secrets(
        answer,
        store,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        runtime_dir=runtime,
    )

    assert not answer.exists()
    with pytest.raises(FileNotFoundError):
        store.load_text()
