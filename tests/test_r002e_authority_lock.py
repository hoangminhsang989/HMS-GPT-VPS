from __future__ import annotations

import inspect
from pathlib import Path
from threading import Event, Thread

import pytest

from hms_gpt_vps.authority_lock import (
    AuthorityLockError,
    _windows_mutex_name,
    exclusive_authority_lock,
)
from hms_gpt_vps import authority_lock as lock_module


def test_authority_lock_serializes_contenders_and_survives_release(tmp_path: Path) -> None:
    lock_path = tmp_path / "state.lock"
    entered = Event()
    release = Event()

    def holder() -> None:
        with exclusive_authority_lock(lock_path, timeout_seconds=2):
            entered.set()
            assert release.wait(2)

    thread = Thread(target=holder)
    thread.start()
    assert entered.wait(2)

    with pytest.raises(AuthorityLockError, match="timed out"):
        with exclusive_authority_lock(lock_path, timeout_seconds=0.1):
            raise AssertionError("contending authority lock must not enter")

    release.set()
    thread.join(timeout=2)
    assert not thread.is_alive()

    # The rendezvous file is intentionally persistent; OS lock ownership, not
    # file existence, controls exclusion and is released when the holder exits.
    assert lock_path.is_file()
    with exclusive_authority_lock(lock_path, timeout_seconds=1):
        pass


def test_authority_lock_rejects_redirected_lock_path(tmp_path: Path) -> None:
    target = tmp_path / "target.lock"
    target.write_bytes(b"\0")
    link = tmp_path / "redirected.lock"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("host does not permit creating a file symlink")

    with pytest.raises(AuthorityLockError, match="link or reparse"):
        with exclusive_authority_lock(link):
            raise AssertionError("redirected authority lock must not enter")


def test_authority_lock_rejects_target_substitution_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "authority.lock"
    displaced = tmp_path / "opened.lock"
    original_open = lock_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated:
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_bytes(b"\0")
        return fd

    monkeypatch.setattr(lock_module.os, "open", racing_open)

    with pytest.raises(AuthorityLockError, match="identity changed during open"):
        with exclusive_authority_lock(path):
            raise AssertionError("substituted authority lock must not enter")

    assert path.exists()
    assert displaced.exists()


def test_windows_mutex_namespace_is_case_insensitive_and_path_opaque(tmp_path: Path) -> None:
    path = (tmp_path / "State.Lock").absolute()
    same_windows_path_case_variant = Path(str(path).upper())

    first = _windows_mutex_name(path)
    second = _windows_mutex_name(same_windows_path_case_variant)

    assert first == second
    assert first.startswith("Local\\HMS-GPT-VPS-Authority-")
    assert len(first.rsplit("-", 1)[-1]) == 64
    assert str(path).casefold() not in first.casefold()


def test_windows_authority_path_uses_kernel_mutex_not_crt_file_lock() -> None:
    source = inspect.getsource(lock_module)
    assert "CreateMutexW" in source
    assert "WaitForSingleObject" in source
    assert "WAIT_ABANDONED" in source
    assert "msvcrt.locking" not in source


def test_authority_lock_rejects_boolean_timeout(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="timeout"):
        with exclusive_authority_lock(tmp_path / "authority.lock", timeout_seconds=True):
            pass


@pytest.mark.parametrize("timeout", [float("nan"), float("inf"), float("-inf")])
def test_authority_lock_rejects_non_finite_timeout(tmp_path: Path, timeout: float) -> None:
    with pytest.raises(ValueError, match="finite"):
        with exclusive_authority_lock(tmp_path / "authority.lock", timeout_seconds=timeout):
            pass
