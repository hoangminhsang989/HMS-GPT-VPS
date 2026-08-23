from __future__ import annotations

import pytest

from hms_gpt_vps.agent_health_contract import (
    AgentHealthExpectation,
    DEFAULT_REQUIRED_CAPABILITIES,
    parse_agent_health,
)
from hms_gpt_vps.agent_health_probe import (
    AgentHealthProbeConfig,
    build_agent_health_probe_script,
)


def valid_health() -> dict[str, object]:
    return {
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
    }


def test_agent_health_accepts_exact_managed_identity_and_capabilities() -> None:
    document = parse_agent_health(
        valid_health(),
        AgentHealthExpectation(instance_id="hms-01"),
    )
    assert document.status == "ok"
    assert document.instance_id == "hms-01"
    assert document.capability_set() >= DEFAULT_REQUIRED_CAPABILITIES


def test_agent_health_rejects_wrong_instance_workspace_or_privilege() -> None:
    payload = valid_health()
    payload["instance_id"] = "other"
    with pytest.raises(ValueError, match="instance_id"):
        parse_agent_health(payload, AgentHealthExpectation(instance_id="hms-01"))

    payload = valid_health()
    payload["workspace_root"] = r"C:\Other"
    with pytest.raises(ValueError, match="workspace_root"):
        parse_agent_health(payload, AgentHealthExpectation(instance_id="hms-01"))

    payload = valid_health()
    payload["privilege"] = "admin"
    with pytest.raises(ValueError, match="non-admin"):
        parse_agent_health(payload, AgentHealthExpectation(instance_id="hms-01"))


def test_agent_health_rejects_public_listener_and_missing_capability() -> None:
    payload = valid_health()
    payload["listener_scope"] = "0.0.0.0"
    with pytest.raises(ValueError, match="loopback-only"):
        parse_agent_health(payload, AgentHealthExpectation(instance_id="hms-01"))

    payload = valid_health()
    payload["capabilities"] = ["workspace.read"]
    with pytest.raises(ValueError, match="missing required capabilities"):
        parse_agent_health(payload, AgentHealthExpectation(instance_id="hms-01"))


def test_agent_health_rejects_duplicate_or_secret_bearing_document() -> None:
    payload = valid_health()
    payload["capabilities"] = ["workspace.read", "workspace.read"]
    with pytest.raises(ValueError, match="duplicates"):
        parse_agent_health(
            payload,
            AgentHealthExpectation(
                instance_id="hms-01",
                required_capabilities=frozenset({"workspace.read"}),
            ),
        )

    payload = valid_health()
    payload["diagnostics"] = {"token": "must-never-be-exposed"}
    with pytest.raises(ValueError, match="secret-bearing field"):
        parse_agent_health(payload, AgentHealthExpectation(instance_id="hms-01"))


def test_health_probe_is_loopback_only_and_fixed_path() -> None:
    config = AgentHealthProbeConfig(port=8765)
    script = build_agent_health_probe_script(config)
    assert "http://127.0.0.1:8765/healthz" in script
    assert "0.0.0.0" not in script
    assert "Invoke-RestMethod" in script
    assert "-MaximumRedirection 0" in script

    with pytest.raises(ValueError, match="canonical /healthz"):
        AgentHealthProbeConfig(path="/other").validate()
