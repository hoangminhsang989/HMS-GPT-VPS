from __future__ import annotations

from pathlib import Path

from .agent_package_transfer_attempt import AgentPackageTransferAttemptStore
from .windows_dpapi import DpapiSecretStore


TRANSFER_ATTEMPT_METADATA_FILENAME = "agent-package-transfer-attempt.json"
TRANSFER_ATTEMPT_TOKEN_FILENAME = "agent-package-transfer-token.dpapi"


def create_dpapi_agent_package_transfer_attempt_store(
    instance_runtime_dir: Path,
) -> AgentPackageTransferAttemptStore:
    """Create the production current-user-DPAPI transfer-attempt store.

    The caller supplies an already instance-scoped host runtime directory. The
    non-secret metadata and protected destructive ownership token use distinct
    fixed filenames so ordinary diagnostics never need to read the DPAPI blob.
    """
    runtime_dir = instance_runtime_dir.expanduser().absolute()
    if runtime_dir.exists() and (not runtime_dir.is_dir() or runtime_dir.is_symlink()):
        raise ValueError("instance runtime directory is unsafe")
    runtime_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = runtime_dir / TRANSFER_ATTEMPT_METADATA_FILENAME
    token_path = runtime_dir / TRANSFER_ATTEMPT_TOKEN_FILENAME
    return AgentPackageTransferAttemptStore(
        metadata_path,
        DpapiSecretStore(token_path),
    )
