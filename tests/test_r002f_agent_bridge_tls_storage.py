from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.agent_bridge_tls_storage as storage_module
from hms_gpt_vps.agent_bridge_tls_storage import (
    AgentBridgePrivateKeyStorageConfig,
    AgentBridgeTlsStorageError,
    build_agent_bridge_private_key_storage_script,
    ensure_agent_bridge_private_key_storage,
    prove_agent_bridge_process_reader_identity,
)


_SERVICE_SID = "S-1-5-80-123-456-789-1011-1213"
_KEY_SHA256 = "a" * 64


def _config(tmp_path: Path) -> AgentBridgePrivateKeyStorageConfig:
    root = tmp_path / "tls-private-key"
    return AgentBridgePrivateKeyStorageConfig(
        storage_root=root,
        private_key_path=root / "agent-bridge-private-key.pem",
        private_key_file_sha256=_KEY_SHA256,
        bridge_reader_sid=_SERVICE_SID,
    )


def _exact_result(
    config: AgentBridgePrivateKeyStorageConfig,
    *,
    changed: bool = False,
) -> dict[str, object]:
    return {
        "ready": True,
        "changed": changed,
        "storage_root": str(config.storage_root.absolute()),
        "private_key_path": str(config.private_key_path.absolute()),
        "private_key_sha256": _KEY_SHA256,
        "storage_owner_sid": "S-1-5-32-544",
        "private_key_owner_sid": "S-1-5-32-544",
        "bridge_reader_sid": _SERVICE_SID,
        "storage_acl_exact": True,
        "private_key_acl_exact": True,
        "storage_entry_count": 1,
        "private_key_reparse_point": False,
        "storage_reparse_point": False,
    }


def test_storage_config_requires_direct_dedicated_child(tmp_path: Path) -> None:
    config = AgentBridgePrivateKeyStorageConfig(
        storage_root=tmp_path / "tls-private-key",
        private_key_path=tmp_path / "tls-private-key" / "nested" / "key.pem",
        private_key_file_sha256=_KEY_SHA256,
        bridge_reader_sid=_SERVICE_SID,
    )

    with pytest.raises(AgentBridgeTlsStorageError, match="direct child"):
        config.validate()


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-1-0",
        "S-1-5-7",
        "S-1-5-11",
        "S-1-5-32-545",
        "S-1-5-18",
        "not-a-sid",
    ],
)
def test_storage_config_rejects_broad_or_nonservice_reader(
    tmp_path: Path,
    sid: str,
) -> None:
    config = AgentBridgePrivateKeyStorageConfig(
        storage_root=tmp_path / "tls-private-key",
        private_key_path=tmp_path / "tls-private-key" / "key.pem",
        private_key_file_sha256=_KEY_SHA256,
        bridge_reader_sid=sid,
    )

    with pytest.raises(AgentBridgeTlsStorageError):
        config.validate()


def test_storage_script_pins_content_directory_and_exact_acl(
    tmp_path: Path,
) -> None:
    script = build_agent_bridge_private_key_storage_script(_config(tmp_path))

    assert "SetAccessRuleProtection($true, $false)" in script
    assert "DirectorySecurity" in script
    assert "FileSecurity" in script
    assert "Get-FileHash" in script
    assert "S-1-5-18" in script
    assert "S-1-5-32-544" in script
    assert _SERVICE_SID in script
    assert "Dedicated TLS storage root contains unexpected entries" in script
    assert "Remove-Item" not in script
    assert "icacls" not in script.lower()


def test_ensure_storage_accepts_exact_observed_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    observed = _exact_result(config, changed=True)

    monkeypatch.setattr(
        storage_module,
        "run_powershell_json",
        lambda script, *, timeout_seconds: dict(observed),
    )

    assert ensure_agent_bridge_private_key_storage(config) == observed


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("ready", "true"),
        ("changed", 1),
        ("storage_acl_exact", False),
        ("private_key_acl_exact", False),
        ("storage_entry_count", 2),
        ("private_key_reparse_point", True),
        ("storage_reparse_point", True),
        ("storage_owner_sid", "S-1-1-0"),
        ("private_key_sha256", "d" * 64),
    ],
)
def test_ensure_storage_rejects_inexact_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    value: object,
) -> None:
    config = _config(tmp_path)
    observed = _exact_result(config)
    observed[key] = value
    monkeypatch.setattr(
        storage_module,
        "run_powershell_json",
        lambda script, *, timeout_seconds: dict(observed),
    )

    with pytest.raises(AgentBridgeTlsStorageError):
        ensure_agent_bridge_private_key_storage(config)


def test_process_identity_requires_exact_service_sid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(
        storage_module,
        "run_powershell_json",
        lambda script, *, timeout_seconds: {
            "process_sid": _SERVICE_SID,
            "identity_name": r"NT SERVICE\HMSBridge",
            "dedicated_service_sid": True,
        },
    )

    proof = prove_agent_bridge_process_reader_identity(config)

    assert proof["process_sid"] == _SERVICE_SID


def test_process_identity_rejects_system_or_interactive_admin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    monkeypatch.setattr(
        storage_module,
        "run_powershell_json",
        lambda script, *, timeout_seconds: {
            "process_sid": "S-1-5-18",
            "identity_name": r"NT AUTHORITY\SYSTEM",
            "dedicated_service_sid": False,
        },
    )

    with pytest.raises(
        AgentBridgeTlsStorageError,
        match="configured service SID",
    ):
        prove_agent_bridge_process_reader_identity(config)
