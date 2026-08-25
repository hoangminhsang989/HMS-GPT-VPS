from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_package_transfer_attempt_factory import (
    TransferTokenDpapiStore,
)
from hms_gpt_vps.principal_binding_registry_authority import (
    PinnedDpapiPrincipalBindingRegistry,
)
from hms_gpt_vps.principal_pairing_service import PrincipalBindingError


def _replace_directory(path: Path) -> Path:
    old = path.with_name(path.name + "-old")
    path.rename(old)
    path.mkdir()
    return old


def test_transfer_token_store_rejects_normal_parent_directory_substitution(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "secrets"
    parent.mkdir()
    store = TransferTokenDpapiStore(parent / "token.dpapi")

    old = _replace_directory(parent)
    assert old.is_dir()
    assert parent.is_dir()

    with pytest.raises(ValueError, match="parent authority changed"):
        store._assert_authority()

    assert not (parent / "token.dpapi").exists()


def test_principal_binding_registry_rejects_root_substitution(
    tmp_path: Path,
) -> None:
    root = tmp_path / "principal-bindings"
    root.mkdir()
    registry = PinnedDpapiPrincipalBindingRegistry(root)

    old = _replace_directory(root)
    assert old.is_dir()
    assert root.is_dir()

    with pytest.raises(
        PrincipalBindingError,
        match="root authority changed",
    ):
        registry.store_for("a" * 64, "hms-01")


def test_transfer_store_can_pin_parent_lazily_when_constructor_precedes_parent(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "later"
    store = TransferTokenDpapiStore(parent / "token.dpapi")
    parent.mkdir()

    store._assert_authority()
    old = _replace_directory(parent)
    assert old.is_dir()

    with pytest.raises(ValueError, match="parent authority changed"):
        store._assert_authority()
