from __future__ import annotations

from copy import deepcopy

import pytest

from hms_gpt_vps import guest_bootstrap as bootstrap_module
from hms_gpt_vps.guest_bootstrap import GuestBootstrapConfig, apply_guest_foundation
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


def _credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential(username="HMSBootstrap", password="secret")


def _config() -> GuestBootstrapConfig:
    return GuestBootstrapConfig(network=bootstrap_module.HyperVNetworkConfig())


def _valid_payload(config: GuestBootstrapConfig) -> dict[str, object]:
    return {
        "ready": True,
        "computer_name": "HMS-GUEST",
        "adapter_name": "Ethernet",
        "interface_index": 7,
        "guest_ipv4": config.network.guest_ipv4,
        "prefix_length": config.network.prefix_length,
        "gateway": config.network.gateway,
        "dns": list(config.network.dns_servers),
        "workspace": config.workspace_path,
        "runtime": config.runtime_path,
    }


def _apply(
    monkeypatch: pytest.MonkeyPatch,
    payload: dict[str, object],
    config: GuestBootstrapConfig,
) -> dict[str, object]:
    monkeypatch.setattr(
        bootstrap_module,
        "run_vm_powershell_json",
        lambda *args, **kwargs: deepcopy(payload),
    )
    return apply_guest_foundation(
        "HMS-GPT-VPS-01",
        _credential(),
        config,
    )


def test_guest_bootstrap_rejects_truthy_string_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    payload = _valid_payload(config)
    payload["ready"] = "false"

    with pytest.raises(RuntimeError, match="postcondition failed"):
        _apply(monkeypatch, payload, config)


def test_guest_bootstrap_rejects_extra_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    payload = _valid_payload(config)
    payload["dns"] = [*config.network.dns_servers, "9.9.9.9"]

    with pytest.raises(RuntimeError, match="DNS evidence differs"):
        _apply(monkeypatch, payload, config)


def test_guest_bootstrap_rejects_wrong_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    config = _config()
    payload = _valid_payload(config)
    payload["guest_ipv4"] = "172.29.240.99"

    with pytest.raises(RuntimeError, match="IPv4 evidence differs"):
        _apply(monkeypatch, payload, config)


def test_guest_bootstrap_rejects_boolean_interface_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    payload = _valid_payload(config)
    payload["interface_index"] = True

    with pytest.raises(RuntimeError, match="interface_index evidence is invalid"):
        _apply(monkeypatch, payload, config)


def test_guest_bootstrap_rejects_unknown_result_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    payload = _valid_payload(config)
    payload["unexpected"] = True

    with pytest.raises(RuntimeError, match="schema is invalid"):
        _apply(monkeypatch, payload, config)


def test_guest_bootstrap_accepts_exact_config_bound_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config()
    payload = _valid_payload(config)

    assert _apply(monkeypatch, payload, config) == payload


@pytest.mark.parametrize("timeout", [True, 0, 601, 1.5])
def test_guest_bootstrap_rejects_invalid_timeout(timeout: object) -> None:
    with pytest.raises(ValueError, match="timeout_seconds"):
        apply_guest_foundation(
            "HMS-GPT-VPS-01",
            _credential(),
            _config(),
            timeout_seconds=timeout,  # type: ignore[arg-type]
        )
