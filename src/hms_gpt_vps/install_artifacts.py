from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Protocol

from .answer_media import AnswerMediaArtifact, build_answer_media_iso
from .bootstrap_credentials import BootstrapCredential, generate_bootstrap_credential
from .unattend import (
    BootstrapAccount,
    InstallUnattendConfig,
    UnattendConfig,
    generate_install_unattend,
)
from .windows_dpapi import DpapiSecretStore


class TextSecretStore(Protocol):
    def save_text(self, secret: str) -> None: ...

    def load_text(self) -> str: ...

    def clear(self) -> None: ...


@dataclass(frozen=True)
class InstallArtifacts:
    answer_iso: Path
    answer_iso_sha256: str
    answer_iso_size: int
    bootstrap_username: str


def _serialize_credential(credential: BootstrapCredential) -> str:
    return json.dumps(
        {"username": credential.username, "password": credential.password},
        separators=(",", ":"),
    )


def _deserialize_credential(payload: str) -> BootstrapCredential:
    raw = json.loads(payload)
    if not isinstance(raw, dict):
        raise ValueError("bootstrap credential payload must be an object")
    username = raw.get("username")
    password = raw.get("password")
    if not isinstance(username, str) or not isinstance(password, str):
        raise ValueError("bootstrap credential payload is invalid")
    return BootstrapCredential(username=username, password=password)


def prepare_install_artifacts(
    runtime_dir: Path,
    base: UnattendConfig,
    *,
    image_index: int = 1,
    credential: BootstrapCredential | None = None,
    secret_store: TextSecretStore | None = None,
) -> InstallArtifacts:
    """Create the transient answer media and encrypted resume credential.

    Production callers use current-user Windows DPAPI by default. Tests may
    inject an in-memory store. Returned metadata never contains the password.
    """
    runtime_dir = runtime_dir.expanduser().resolve()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    credential = credential or generate_bootstrap_credential()
    store = secret_store or DpapiSecretStore(runtime_dir / "bootstrap.dpapi")

    install_config = InstallUnattendConfig(
        base=base,
        bootstrap=BootstrapAccount(
            username=credential.username,
            password=credential.password,
        ),
        image_index=image_index,
        dedicated_blank_disk_acknowledged=True,
    )
    xml = generate_install_unattend(install_config)

    store.save_text(_serialize_credential(credential))
    answer_path = runtime_dir / "hms-answer.iso"
    try:
        artifact: AnswerMediaArtifact = build_answer_media_iso(answer_path, xml)
    except Exception:
        store.clear()
        raise

    return InstallArtifacts(
        answer_iso=artifact.path,
        answer_iso_sha256=artifact.sha256,
        answer_iso_size=artifact.size,
        bootstrap_username=credential.username,
    )


def load_bootstrap_credential(store: TextSecretStore) -> BootstrapCredential:
    return _deserialize_credential(store.load_text())


def clear_install_secrets(answer_iso: Path, store: TextSecretStore) -> None:
    """Remove only known transient provisioning secrets after guest bootstrap."""
    answer_iso.unlink(missing_ok=True)
    store.clear()
