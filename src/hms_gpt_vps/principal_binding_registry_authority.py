from __future__ import annotations

import hashlib
import os
from pathlib import Path

from .agent_package_transfer_attempt_factory import TransferTokenDpapiStore
from .principal_pairing_service import (
    PrincipalBindingError,
    PrincipalSessionBindingStore,
)
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
    require_existing_directory,
)


_HEX_LOWER = frozenset("0123456789abcdef")


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _canonical_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in _HEX_LOWER for char in value)
    ):
        raise PrincipalBindingError(
            f"{name} must be canonical lowercase SHA-256"
        )
    return value


def _instance_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
    ):
        raise PrincipalBindingError("instance_id is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PrincipalBindingError(
            "instance_id contains control characters"
        )
    return value


class PinnedDpapiPrincipalBindingRegistry:
    """DPAPI principal bindings pinned to one startup directory identity."""

    def __init__(self, root: Path) -> None:
        authority = lexical_absolute(root)
        if path_chain_has_redirect(authority):
            raise PrincipalBindingError(
                "principal binding root traverses a link or reparse point"
            )
        self.root = require_existing_directory(
            authority,
            label="principal binding root",
        )
        self._root_identity = self.root.stat()

    def _assert_root_authority(self) -> None:
        if path_chain_has_redirect(self.root):
            raise PrincipalBindingError(
                "principal binding root traverses a link or reparse point"
            )
        try:
            current = require_existing_directory(
                self.root,
                label="principal binding root",
            ).stat()
        except (FileNotFoundError, PermissionError) as exc:
            raise PrincipalBindingError(
                "principal binding root authority is unavailable"
            ) from exc
        if not _same_file_identity(self._root_identity, current):
            raise PrincipalBindingError(
                "principal binding root authority changed"
            )

    def store_for(
        self,
        principal_sha256: str,
        instance_id: str,
    ) -> PrincipalSessionBindingStore:
        principal_digest = _canonical_sha256(
            principal_sha256,
            "principal_sha256",
        )
        checked_instance = _instance_id(instance_id)
        self._assert_root_authority()
        instance_digest = hashlib.sha256(
            checked_instance.encode("utf-8")
        ).hexdigest()
        path = self.root / (
            f"principal-{principal_digest}-instance-{instance_digest}.dpapi"
        )
        store = PrincipalSessionBindingStore(
            TransferTokenDpapiStore(path)
        )
        self._assert_root_authority()
        return store
