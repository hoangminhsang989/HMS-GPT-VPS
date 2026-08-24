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
    assert store.secret_store.path != store.metadata_path


def test_production_transfer_attempt_factory_rejects_non_directory_runtime_path(
    tmp_path: Path,
) -> None:
    runtime_path = tmp_path / "not-a-directory"
    runtime_path.write_text("occupied", encoding="utf-8")

    with pytest.raises(ValueError, match="runtime directory is unsafe"):
        create_dpapi_agent_package_transfer_attempt_store(runtime_path)
