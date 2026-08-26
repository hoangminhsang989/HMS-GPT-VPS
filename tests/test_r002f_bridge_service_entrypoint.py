from __future__ import annotations

from pathlib import Path
import json

import pytest

import hms_gpt_vps.bridge_service_entrypoint as entry_module
from hms_gpt_vps.bridge_cli import build_parser
from hms_gpt_vps.bridge_pairing_surface_runtime import BridgePairingSurfaceRuntime
from hms_gpt_vps.bridge_production_service_runtime import BridgeProductionServiceRuntime
from hms_gpt_vps.bridge_service_entrypoint import (
    _default_oauth_verifier_loader,
    build_hms_bridge_runtime_factory,
    resolve_hms_bridge_service_sid,
    run_hms_bridge_service_entrypoint,
)
from hms_gpt_vps.bridge_service_runtime_config import BridgeServiceRuntimeConfig


_SERVICE_SID = "S-1-5-80-123-456-789-1011-1213"
_VM_ID = "12345678-1234-1234-1234-123456789abc"


class _Verifier:
    async def verify_token(self, token: str):
        return None


def _config(tmp_path: Path) -> BridgeServiceRuntimeConfig:
    runtime_root = tmp_path / "runtime"
    (runtime_root / "secrets").mkdir(parents=True)
    tls_root = tmp_path / "tls-private-key"
    return BridgeServiceRuntimeConfig(
        schema_version=1,
        instance_id="HMS-VPS-1",
        runtime_root=str(runtime_root),
        provision_state_path=str(runtime_root / "provision-state.json"),
        bridge_base_url="https://bridge.example.test",
        mcp_issuer_url="https://issuer.example.test",
        mcp_resource_server_url="https://resource.example.test",
        mcp_port=8765,
        presence_max_age_seconds=90,
        pair_ttl_seconds=300,
        tls_certificate_path=str(tmp_path / "agent-bridge.pem"),
        tls_private_key_path=str(tls_root / "agent-bridge-private-key.pem"),
        tls_storage_root=str(tls_root),
        tls_certificate_der_sha256="b" * 64,
        tls_private_key_file_sha256="a" * 64,
        tls_port=9443,
        vm_id=_VM_ID,
        vm_name="HMS-VPS-1",
        trust_root_der_sha256="c" * 64,
    )


def test_runtime_factory_is_lazy_and_wraps_pairing_surface_after_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    events: list[str] = []
    base_runtime = object.__new__(BridgeProductionServiceRuntime)
    wrapped_runtime = object.__new__(BridgePairingSurfaceRuntime)

    monkeypatch.setattr(
        entry_module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: events.append("identity") or {"process_sid": sid},
    )
    monkeypatch.setattr(
        entry_module,
        "build_bridge_production_service_runtime",
        lambda runtime_config, verifier: events.append("build") or base_runtime,
    )

    def load_config() -> BridgeServiceRuntimeConfig:
        events.append("config")
        return config

    def load_verifier(checked: BridgeServiceRuntimeConfig):
        assert checked is config
        events.append("verifier")
        return _Verifier()

    def wrap(inner: BridgeProductionServiceRuntime, sid: str):
        assert inner is base_runtime
        assert sid == _SERVICE_SID
        events.append("wrap")
        return wrapped_runtime

    factory = build_hms_bridge_runtime_factory(
        _SERVICE_SID,
        config_loader=load_config,
        verifier_loader=load_verifier,
        runtime_wrapper=wrap,
    )
    assert events == []
    assert factory() is wrapped_runtime
    assert events == ["identity", "config", "verifier", "build", "wrap"]


def test_service_entrypoint_passes_lazy_factory_before_config_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    def config_loader():
        events.append("config")
        raise AssertionError("SCM host must own the identity-before-config boundary")

    def fake_host(*, expected_service_sid, runtime_factory):
        events.append("host")
        assert expected_service_sid == _SERVICE_SID
        assert callable(runtime_factory)

    monkeypatch.setattr(
        entry_module,
        "run_hms_bridge_windows_service",
        fake_host,
    )

    run_hms_bridge_service_entrypoint(
        sid_resolver=lambda: events.append("sid") or _SERVICE_SID,
        config_loader=config_loader,
        verifier_loader=lambda config: _Verifier(),
        runtime_wrapper=lambda inner, sid: pytest.fail("factory must stay lazy"),
    )
    assert events == ["sid", "host"]


def test_default_oauth_verifier_loader_uses_protected_machine_credential_then_discovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    events: list[object] = []
    credential = object()
    verifier = _Verifier()
    monkeypatch.setattr(
        entry_module,
        "load_protected_bridge_oauth_introspection_credential",
        lambda issuer: events.append(("credential", issuer)) or credential,
    )
    monkeypatch.setattr(
        entry_module,
        "build_bridge_oauth_introspection_verifier_sync",
        lambda observed, resource: (
            events.append(("verifier", observed, resource)) or verifier
        ),
    )
    assert _default_oauth_verifier_loader(config) is verifier
    assert events == [
        ("credential", config.mcp_issuer_url),
        ("verifier", credential, config.mcp_resource_server_url),
    ]


def test_service_sid_resolver_requires_exact_virtual_account_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        entry_module,
        "run_powershell_json",
        lambda script, timeout_seconds: {
            "service_account": r"NT SERVICE\HMSBridge",
            "service_sid": _SERVICE_SID,
        },
    )
    assert resolve_hms_bridge_service_sid() == _SERVICE_SID


def test_pairing_link_cli_uses_pid_pinned_ipc_and_prints_result(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import sys
    import hms_gpt_vps.bridge_cli as cli_module
    import hms_gpt_vps.bridge_pairing_link_ipc as ipc_module
    from hms_gpt_vps.bridge_pairing_link_ipc import PairingLinkIpcResult

    monkeypatch.setattr(
        ipc_module,
        "request_pairing_link_from_running_hms_bridge",
        lambda: PairingLinkIpcResult(
            "pair-1",
            "2026-08-26T01:02:03Z",
            "https://bridge.example.test/pair/pair-1#token=abc",
        ),
    )
    monkeypatch.setattr(sys, "argv", ["hms-bridge", "pairing-link"])
    assert cli_module.main() == 0
    assert json.loads(capsys.readouterr().out) == {
        "pair_id": "pair-1",
        "expires_at": "2026-08-26T01:02:03Z",
        "pairing_link": "https://bridge.example.test/pair/pair-1#token=abc",
    }


def test_bridge_cli_has_no_config_or_pid_override() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["service", "--config", "attacker.json"])
    with pytest.raises(SystemExit):
        parser.parse_args(["pairing-link", "--pid", "1234"])
    with pytest.raises(SystemExit):
        parser.parse_args(["pairing-link", "--config", "attacker.json"])
    assert parser.parse_args(["service"]).command == "service"
    assert parser.parse_args(["pairing-link"]).command == "pairing-link"
