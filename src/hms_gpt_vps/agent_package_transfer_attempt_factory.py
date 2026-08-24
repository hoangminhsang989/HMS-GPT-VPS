from __future__ import annotations

from pathlib import Path

from .agent_package_transfer_attempt import AgentPackageTransferAttemptStore
from .windows_dpapi import DpapiSecretStore


TRANSFER_ATTEMPT_METADATA_FILENAME = "agent-package-transfer-attempt.json"
TRANSFER_ATTEMPT_TOKEN_FILENAME = "agent-package-transfer-token.dpapi"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _assert_path_chain_not_reparse(path: Path) -> None:
    """Reject symlink/reparse components in the host authority-store path."""
    chain: list[Path] = []
    current = path
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent

    for candidate in reversed(chain):
        if candidate.is_symlink():
            raise ValueError("instance runtime directory path must not traverse a symbolic link")
        try:
            stat_result = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(stat_result, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("instance runtime directory path must not traverse a reparse point")


def create_dpapi_agent_package_transfer_attempt_store(
    instance_runtime_dir: Path,
) -> AgentPackageTransferAttemptStore:
    """Create the production current-user-DPAPI transfer-attempt store.

    The caller supplies an instance-scoped host runtime directory. Every existing
    path component is required to be a normal directory path rather than a
    symlink/reparse redirect because the DPAPI token authorizes cleanup of one
    ownership-marked guest staging root. The returned store also receives the
    lexical DPAPI token path so it can revalidate both authority paths on every
    later read/write/delete instead of trusting only this factory-time check.
    """
    runtime_dir = instance_runtime_dir.expanduser().absolute()
    _assert_path_chain_not_reparse(runtime_dir)
    if runtime_dir.exists() and not runtime_dir.is_dir():
        raise ValueError("instance runtime directory is unsafe")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    _assert_path_chain_not_reparse(runtime_dir)
    if not runtime_dir.is_dir():
        raise ValueError("instance runtime directory is unsafe")

    metadata_path = runtime_dir / TRANSFER_ATTEMPT_METADATA_FILENAME
    token_path = runtime_dir / TRANSFER_ATTEMPT_TOKEN_FILENAME
    return AgentPackageTransferAttemptStore(
        metadata_path,
        DpapiSecretStore(token_path),
        secret_path=token_path,
    )
