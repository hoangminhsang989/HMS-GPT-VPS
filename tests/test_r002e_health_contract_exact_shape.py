from __future__ import annotations

import pytest

from hms_gpt_vps.agent_health_contract import (
    DEFAULT_REQUIRED_CAPABILITIES,
    AgentHealthExpectation,
    parse_agent_health,
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
        "boot_id": "boot-01",
    }


def expectation() -> AgentHealthExpectation:
    return AgentHealthExpectation(instance_id="hms-01")


def test_health_contract_rejects_unknown_nonsecret_fields() -> None:
    payload = valid_health()
    payload["future_semantics"] = "must-require-schema-bump"

    with pytest.raises(ValueError, match="unknown=future_semantics"):
        parse_agent_health(payload, expectation())


def test_health_contract_rejects_missing_fields_with_exact_shape_error() -> None:
    payload = valid_health()
    payload.pop("boot_id")

    with pytest.raises(ValueError, match="missing=boot_id"):
        parse_agent_health(payload, expectation())


def test_health_contract_keeps_secret_field_rejection_precedence() -> None:
    payload = valid_health()
    payload["diagnostics"] = {"token": "must-not-be-exposed"}

    with pytest.raises(ValueError, match="secret-bearing field"):
        parse_agent_health(payload, expectation())
