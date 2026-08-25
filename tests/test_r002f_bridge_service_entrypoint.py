from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.bridge_service_entrypoint as entry_module
from hms_gpt_vps.bridge_cli import build_parser
from hms_gpt_vps.bridge_service_entrypoint import (
    BridgeOAuthVerifierAuthorityUnavailableError,
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


def test_runtime_factory_is_lazy_and_preserves_security_ordering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    events: list[str] = []
    sentinel = object()

    monkeypatch.setattr(
        entry_module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: events.append("identity") or {"process_sid": sid},
    )
    monkeypatch.setattr(
        entry_module,
        "build_bridge_production_service_runtime",
        lambda runtime_config, verifier: events.append("build") or sentinel,
    )

    def load_config() -> BridgeServiceRuntimeConfig:
        events.append("config")
        return config

    def load_verifier(checked: BridgeServiceRuntimeConfig):
        assert checked is config
        events.append("verifier")
        return _Verifier()

    factory = build_hms_bridge_runtime_factory(
        _SERVICE_SID,
        config_loader=load_config,
        verifier_loader=load_verifier,
    )
    assert events == []
    assert factory() is sentinel
    assert events == ["identity", "config", "verifier", "build"]


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
        # Deliberately do not invoke the factory: this proves entrypoint setup
        # itself does not read fixed runtime config or secrets.

    monkeypatch.setattr(
        entry_module,
        "run_hms_bridge_windows_service",
        fake_host,
    )

    run_hms_bridge_service_entrypoint(
        sid_resolver=lambda: events.append("sid") or _SERVICE_SID,
        config_loader=config_loader,
        verifier_loader=lambda config: _Verifier(),
    )
    assert events == ["sid", "host"]


def test_default_oauth_verifier_loader_fails_closed(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with pytest.raises(
        BridgeOAuthVerifierAuthorityUnavailableError,
        match="not provisioned",
    ):
        _default_oauth_verifier_loader(config)


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


def test_bridge_cli_has_no_config_override() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["service", "--config", "attacker.json"])
    args = parser.parse_args(["service"])
    assert args.command == "service"
