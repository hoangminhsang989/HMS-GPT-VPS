from __future__ import annotations

import base64
import json

import pytest

from hms_gpt_vps.agent_health_contract import (
    AgentHealthExpectation,
    DEFAULT_REQUIRED_CAPABILITIES,
    parse_agent_health,
)
from hms_gpt_vps.agent_health_probe import (
    AgentHealthProbeConfig,
    AgentHealthProbeError,
    build_agent_health_probe_script,
    validate_agent_application_health_evidence,
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


def evidence(
    payload: object,
    *,
    config: AgentHealthProbeConfig | None = None,
) -> dict[str, object]:
    probe = config or AgentHealthProbeConfig(port=8765)
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return {
        "uri": probe.uri,
        "status_code": 200,
        "content_type": "application/json; charset=utf-8",
        "body_bytes": len(raw),
        "body_b64": base64.b64encode(raw).decode("ascii"),
        "redirects_allowed": False,
        "proxy_enabled": False,
    }


def expectation() -> AgentHealthExpectation:
    return AgentHealthExpectation(instance_id="hms-01")


def test_agent_health_accepts_exact_managed_identity_and_capabilities() -> None:
    document = parse_agent_health(valid_health(), expectation())
    assert document.status == "ok"
    assert document.instance_id == "hms-01"
    assert document.capability_set() >= DEFAULT_REQUIRED_CAPABILITIES


def test_agent_health_rejects_wrong_instance_workspace_or_privilege() -> None:
    payload = valid_health()
    payload["instance_id"] = "other"
    with pytest.raises(ValueError, match="instance_id"):
        parse_agent_health(payload, expectation())

    payload = valid_health()
    payload["workspace_root"] = r"C:\Other"
    with pytest.raises(ValueError, match="workspace_root"):
        parse_agent_health(payload, expectation())

    payload = valid_health()
    payload["privilege"] = "admin"
    with pytest.raises(ValueError, match="non-admin"):
        parse_agent_health(payload, expectation())


def test_agent_health_rejects_public_listener_and_missing_capability() -> None:
    payload = valid_health()
    payload["listener_scope"] = "0.0.0.0"
    with pytest.raises(ValueError, match="loopback-only"):
        parse_agent_health(payload, expectation())

    payload = valid_health()
    payload["capabilities"] = ["workspace.read"]
    with pytest.raises(ValueError, match="missing required capabilities"):
        parse_agent_health(payload, expectation())


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
        parse_agent_health(payload, expectation())


def test_health_probe_is_loopback_only_bounded_and_has_no_redirect_or_proxy() -> None:
    config = AgentHealthProbeConfig(port=8765, timeout_seconds=7, max_body_bytes=8192)
    script = build_agent_health_probe_script(config)

    assert "http://127.0.0.1:8765/healthz" in script
    assert "0.0.0.0" not in script
    assert "HttpWebRequest" in script
    assert "$request.AllowAutoRedirect = $false" in script
    assert "$request.Proxy = $null" in script
    assert "$maxBodyBytes = 8192" in script
    assert "$request.Timeout = 7000" in script
    assert "ToBase64String" in script
    assert "Invoke-RestMethod" not in script

    with pytest.raises(ValueError, match="canonical /healthz"):
        AgentHealthProbeConfig(path="/other").validate()
    with pytest.raises(ValueError, match="between 1024 and 65535"):
        AgentHealthProbeConfig(port=0).validate()
    with pytest.raises(ValueError, match="body limit"):
        AgentHealthProbeConfig(max_body_bytes=512).validate()


def test_application_health_evidence_requires_http_transport_proofs() -> None:
    config = AgentHealthProbeConfig(port=8765)
    good = evidence(valid_health(), config=config)

    document = validate_agent_application_health_evidence(
        good,
        expectation(),
        expected_agent_version="0.1.0",
        config=config,
    )
    assert document.boot_id == "boot-123"

    for field, value, message in (
        ("status_code", 204, "HTTP 200"),
        ("uri", "http://127.0.0.1:9999/healthz", "loopback target"),
        ("content_type", "text/plain", "Content-Type"),
        ("redirects_allowed", True, "redirects"),
        ("proxy_enabled", True, "proxy"),
    ):
        bad = dict(good)
        bad[field] = value
        with pytest.raises(AgentHealthProbeError, match=message):
            validate_agent_application_health_evidence(
                bad,
                expectation(),
                expected_agent_version="0.1.0",
                config=config,
            )


def test_application_health_evidence_requires_exact_approved_version_and_capabilities() -> None:
    config = AgentHealthProbeConfig(port=8765)

    with pytest.raises(AgentHealthProbeError, match="version"):
        validate_agent_application_health_evidence(
            evidence(valid_health(), config=config),
            expectation(),
            expected_agent_version="0.2.0",
            config=config,
        )

    payload = valid_health()
    payload["capabilities"] = sorted(DEFAULT_REQUIRED_CAPABILITIES | {"shell.exec"})
    with pytest.raises(AgentHealthProbeError, match="canonical capability set"):
        validate_agent_application_health_evidence(
            evidence(payload, config=config),
            expectation(),
            expected_agent_version="0.1.0",
            config=config,
        )


def test_application_health_evidence_rejects_corrupt_or_inconsistent_body() -> None:
    config = AgentHealthProbeConfig(port=8765)
    good = evidence(valid_health(), config=config)

    bad = dict(good)
    bad["body_b64"] = "%%%"
    with pytest.raises(AgentHealthProbeError, match="base64"):
        validate_agent_application_health_evidence(
            bad,
            expectation(),
            expected_agent_version="0.1.0",
            config=config,
        )

    bad = dict(good)
    bad["body_bytes"] = int(good["body_bytes"]) + 1
    with pytest.raises(AgentHealthProbeError, match="length"):
        validate_agent_application_health_evidence(
            bad,
            expectation(),
            expected_agent_version="0.1.0",
            config=config,
        )

    not_object = evidence(["not", "an", "object"], config=config)
    with pytest.raises(AgentHealthProbeError, match="JSON body must be an object"):
        validate_agent_application_health_evidence(
            not_object,
            expectation(),
            expected_agent_version="0.1.0",
            config=config,
        )
