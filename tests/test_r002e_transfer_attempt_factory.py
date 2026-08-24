from pathlib import Path

import pytest

from hms_gpt_vps.agent_package_transfer_attempt import AgentPackageTransferPhase
from hms_gpt_vps.agent_package_transfer_attempt_factory import (
    TRANSFER_ATTEMPT_METADATA_FILENAME,
    TRANSFER_ATTEMPT_TOKEN_FILENAME,
    TransferTokenDpapiStore,
    create_dpapi_agent_package_transfer_attempt_store,
)
from hms_gpt_vps import agent_package_transfer_attempt_factory as factory_module
from hms_gpt_vps.windows_dpapi import DpapiSecretStore


def test_production_transfer_attempt_factory_separates_metadata_and_dpapi_token(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "instance-01"
    store = create_dpapi_agent_package_transfer_attempt_store(runtime_dir)

    assert store.metadata_path == runtime_dir / TRANSFER_ATTEMPT_METADATA_FILENAME
    assert isinstance(store.secret_store, DpapiSecretStore)
    assert isinstance(store.secret_store, TransferTokenDpapiStore)
    assert store.secret_store.path == runtime_dir / TRANSFER_ATTEMPT_TOKEN_FILENAME
    assert store.secret_path == runtime_dir / TRANSFER_ATTEMPT_TOKEN_FILENAME
    assert store.secret_store.path != store.metadata_path


def test_production_transfer_attempt_factory_rejects_non_directory_runtime_path(
    tmp_path: Path,
) -> None:
    runtime_path = tmp_path / "not-a-directory"
    runtime_path.write_text("occupied", encoding="utf-8")

    with pytest.raises(ValueError, match="runtime directory is unsafe"):
        create_dpapi_agent_package_transfer_attempt_store(runtime_path)


def test_production_transfer_attempt_factory_rejects_symlinked_parent(
    tmp_path: Path,
) -> None:
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    redirected_parent = tmp_path / "redirected-parent"
    try:
        redirected_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("host does not permit creating a directory symlink")

    with pytest.raises(ValueError, match="must not traverse a symbolic link"):
        create_dpapi_agent_package_transfer_attempt_store(
            redirected_parent / "instance-01"
        )


def test_production_transfer_attempt_store_rechecks_runtime_redirect_after_factory(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "instance-01"
    store = create_dpapi_agent_package_transfer_attempt_store(runtime_dir)
    preserved_runtime = tmp_path / "instance-01-preserved"
    redirected_target = tmp_path / "redirected-target"
    redirected_target.mkdir()

    runtime_dir.rename(preserved_runtime)
    try:
        runtime_dir.symlink_to(redirected_target, target_is_directory=True)
    except OSError:
        preserved_runtime.rename(runtime_dir)
        pytest.skip("host does not permit creating a directory symlink")

    # The store must reject the redirected lexical authority path before it can
    # attempt a DPAPI read from the substituted directory.
    with pytest.raises(ValueError, match="authority path traverses"):
        store.load()


def test_published_clear_leaves_inert_token_ciphertext_and_retry_overwrites_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(factory_module, "protect_bytes", lambda raw: b"P" + raw)
    monkeypatch.setattr(
        factory_module,
        "unprotect_bytes",
        lambda raw: raw[1:] if raw.startswith(b"P") else (_ for _ in ()).throw(ValueError("bad")),
    )
    runtime_dir = tmp_path / "instance-01"
    store = create_dpapi_agent_package_transfer_attempt_store(runtime_dir)
    first = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="a" * 64,
    )
    store.bind_guest_service_interface_baseline(False)
    store.transition(AgentPackageTransferPhase.PLANNED, AgentPackageTransferPhase.TRANSFERRING)
    store.transition(AgentPackageTransferPhase.TRANSFERRING, AgentPackageTransferPhase.PUBLISHED)
    token_path = runtime_dir / TRANSFER_ATTEMPT_TOKEN_FILENAME
    first_ciphertext = token_path.read_bytes()

    store.clear_published()

    assert store.load() is None
    assert (runtime_dir / TRANSFER_ATTEMPT_METADATA_FILENAME).read_bytes() == b""
    assert token_path.read_bytes() == first_ciphertext

    second = store.begin_or_resume(
        instance_id="hms-01",
        vm_name="HMS-GPT-VPS-01",
        manifest_sha256="b" * 64,
    )
    assert second.transfer_id != first.transfer_id
    assert second.ownership_token != first.ownership_token
    assert token_path.read_bytes() != first_ciphertext
    assert store.load().transfer_id == second.transfer_id  # type: ignore[union-attr]


def test_transfer_token_store_rejects_target_substitution_after_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(factory_module, "protect_bytes", lambda raw: b"P" + raw)
    token_path = tmp_path / "token.dpapi"
    token_path.write_bytes(b"Pold")
    store = TransferTokenDpapiStore(token_path)
    displaced = tmp_path / "opened-token.dpapi"
    original_open = factory_module.os.open
    mutated = False

    def racing_open(target, flags, *args, **kwargs):  # type: ignore[no-untyped-def]
        nonlocal mutated
        fd = original_open(target, flags, *args, **kwargs)
        if not mutated:
            mutated = True
            Path(target).replace(displaced)
            Path(target).write_bytes(b"replacement-must-survive")
        return fd

    monkeypatch.setattr(factory_module.os, "open", racing_open)

    with pytest.raises(ValueError, match="authority changed during open"):
        store.save_text("1" * 48)

    assert token_path.read_bytes() == b"replacement-must-survive"
    assert displaced.read_bytes() == b"Pold"
