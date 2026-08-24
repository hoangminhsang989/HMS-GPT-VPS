from pathlib import Path

import pytest

from hms_gpt_vps.agent_package_transfer_attempt_factory import (
    TRANSFER_ATTEMPT_METADATA_FILENAME,
    TRANSFER_ATTEMPT_TOKEN_FILENAME,
    create_dpapi_agent_package_transfer_attempt_store,
)
from hms_gpt_vps.windows_dpapi import DpapiSecretStore


def test_production_transfer_attempt_factory_separates_metadata_and_dpapi_token(
    tmp_path: Path,
) -> None:
    runtime_dir = tmp_path / "instance-01"
    store = create_dpapi_agent_package_transfer_attempt_store(runtime_dir)

    assert store.metadata_path == runtime_dir / TRANSFER_ATTEMPT_METADATA_FILENAME
    assert isinstance(store.secret_store, DpapiSecretStore)
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
