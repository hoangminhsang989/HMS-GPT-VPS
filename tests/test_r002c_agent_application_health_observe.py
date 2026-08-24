from __future__ import annotations

import base64
import json

import pytest

from hms_gpt_vps.agent_health_contract import (
    AgentHealthExpectation,
    DEFAULT_REQUIRED_CAPABILITIES,
    parse_agent_health,
)
from hms_gpt_vps.agent_health_probe import probe_agent_application_health_for_runtime
from hms_gpt_vps.agent_post_install_observe import (
    AgentPostInstallObservationConfig,
    AgentPostInstallObserver,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
    AgentServiceRuntimeConfigError,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential


def runtime_config(*, health_port: int = 8765) -> AgentServiceRuntimeConfig:
    return AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=r"C:\HMS-Workspace",
        state_root=r"C:\ProgramData\HMS-GPT-VPS\State",
        python_executable=r"C:\Program Files\Python\python.exe",
        git_executable=r"C:\Program Files\Git\cmd\git.exe",
        health_port=health_port,
    )


def health_document():
    return parse_agent_health(
        {
            "schema_version": 1,
            "status": "ok",
            "instance_id": "hms-01",
            "agent_version": "0.1.0",
            "workspace_root": r"C:\HMS-Workspace",
            "capabilities": sorted(DEFAULT_REQUIRED_CAPABILITIES),
            "service_identity": r"NT SERVICE\HMSAgent",
            "listener_scope": "loopback-only",
            "privilege": "non-admin",
            "boot_id": "boot-123",
        },
        AgentHealthExpectation(instance_id="hms-01"),
    )


def observer_config() -> AgentPostInstallObservationConfig:
    return AgentPostInstallObservationConfig(
        vm_name="HMS-GPT-VPS-01",
        expected_agent_sha256="a" * 64,
        expected_agent_version="0.1.0",
        service=AgentServiceConfig(),
        runtime=runtime_config(),
    )


def credential() -> PowerShellDirectCredential:
    return PowerShellDirectCredential(username="hmsbootstrap", password="temporary")


def test_service_runtime_config_rejects_ephemeral_health_port() -> None:
    with pytest.raises(AgentServiceRuntimeConfigError, match="stable service port"):
        runtime_config(health_port=0).validate()


def test_observer_does_not_probe_application_when_service_boundary_is_not_ready(monkeypatch) -> None:
    calls: list[str] = []

    def fake_service(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append("service")
        return {"service_ready": False}

    def fake_health(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append("health")
        raise AssertionError("health must not run before service readiness")

    monkeypatch.setattr(
        "hms_gpt_vps.agent_post_install_observe.probe_agent_service_readiness",
        fake_service,
    )
    monkeypatch.setattr(
        "hms_gpt_vps.agent_post_install_observe.probe_agent_application_health_for_runtime",
        fake_health,
    )

    observed = AgentPostInstallObserver(observer_config()).observe(credential())

    assert calls == ["service"]
    assert observed.service_ready is False
    assert observed.agent_healthy is False
    assert observed.health_error == "service_not_ready"
    provision = observed.to_provision_observation()
    assert provision.agent_service_ready is False
    assert provision.agent_healthy is False


def test_observer_sets_agent_healthy_only_after_both_verified_layers(monkeypatch) -> None:
    calls: list[str] = []

    def fake_service(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append("service")
        return {"service_ready": True, "runtime_config_sha256_ok": True}

    def fake_health(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        calls.append("health")
        return health_document()

    monkeypatch.setattr(
        "hms_gpt_vps.agent_post_install_observe.probe_agent_service_readiness",
        fake_service,
    )
    monkeypatch.setattr(
        "hms_gpt_vps.agent_post_install_observe.probe_agent_application_health_for_runtime",
        fake_health,
    )

    observed = AgentPostInstallObserver(observer_config()).observe(credential())

    assert calls == ["service", "health"]
    assert observed.service_ready is True
    assert observed.agent_healthy is True
    assert observed.health is not None
    assert observed.health.boot_id == "boot-123"
    provision = observed.to_provision_observation()
    assert provision.agent_service_ready is True
    assert provision.agent_healthy is True


def test_observer_fails_health_closed_without_persisting_exception_message(monkeypatch) -> None:
    def fake_service(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        return {"service_ready": True}

    def fake_health(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("must-not-persist-secret-like-endpoint-body")

    monkeypatch.setattr(
        "hms_gpt_vps.agent_post_install_observe.probe_agent_service_readiness",
        fake_service,
    )
    monkeypatch.setattr(
        "hms_gpt_vps.agent_post_install_observe.probe_agent_application_health_for_runtime",
        fake_health,
    )

    observed = AgentPostInstallObserver(observer_config()).observe(credential())

    assert observed.service_ready is True
    assert observed.agent_healthy is False
    assert observed.health is None
    assert observed.health_error == "RuntimeError"
    assert "must-not-persist" not in observed.health_error


def test_runtime_health_probe_uses_runtime_instance_workspace_port_and_package_version(monkeypatch) -> None:
    runtime = runtime_config(health_port=9876)
    payload = {
        "schema_version": 1,
        "status": "ok",
        "instance_id": "hms-01",
        "agent_version": "0.1.0",
        "workspace_root": r"C:\HMS-Workspace",
        "capabilities": sorted(DEFAULT_REQUIRED_CAPABILITIES),
        "service_identity": r"NT SERVICE\HMSAgent",
        "listener_scope": "loopback-only",
        "privilege": "non-admin",
        "boot_id": "boot-xyz",
    }
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    captured: dict[str, object] = {}

    def fake_run(vm_name, _credential, script, *, timeout_seconds):  # type: ignore[no-untyped-def]
        captured["vm_name"] = vm_name
        captured["script"] = script
        captured["timeout_seconds"] = timeout_seconds
        return {
            "uri": "http://127.0.0.1:9876/healthz",
            "status_code": 200,
            "content_type": "application/json; charset=utf-8",
            "body_bytes": len(raw),
            "body_b64": base64.b64encode(raw).decode("ascii"),
            "redirects_allowed": False,
            "proxy_enabled": False,
        }

    monkeypatch.setattr("hms_gpt_vps.agent_health_probe.run_vm_powershell_json", fake_run)

    document = probe_agent_application_health_for_runtime(
        "HMS-GPT-VPS-01",
        credential(),
        runtime,
        expected_agent_version="0.1.0",
        timeout_seconds=6,
    )

    assert document.instance_id == runtime.instance_id
    assert document.workspace_root == runtime.workspace_root
    assert document.agent_version == "0.1.0"
    assert "http://127.0.0.1:9876/healthz" in str(captured["script"])
    assert captured["timeout_seconds"] == 21
