from __future__ import annotations

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from hms_gpt_vps.agent_health_contract import (
    AgentHealthExpectation,
    parse_agent_health,
)
from hms_gpt_vps.agent_health_server import (
    AgentHealthServer,
    AgentHealthServerConfig,
    AgentHealthState,
)


def _state() -> AgentHealthState:
    return AgentHealthState(
        instance_id="instance-1",
        agent_version="0.1.0",
        workspace_root=r"C:\HMS-Workspace",
        boot_id="boot-1",
        service_identity=r"NT SERVICE\HMSAgent",
        privilege="non-admin",
    )


def test_health_state_builds_contract_valid_secret_free_document() -> None:
    document = _state().to_document()
    parsed = parse_agent_health(
        document,
        AgentHealthExpectation(instance_id="instance-1"),
    )
    assert parsed.status == "ok"
    assert parsed.listener_scope == "loopback-only"
    assert parsed.boot_id == "boot-1"
    serialized = json.dumps(document).casefold()
    assert "token" not in serialized
    assert "password" not in serialized
    assert "secret" not in serialized


def test_health_server_is_loopback_only_and_serves_healthz() -> None:
    server = AgentHealthServer(
        _state(),
        config=AgentHealthServerConfig(port=0),
    )
    with server:
        port = server.bound_port
        assert isinstance(port, int) and port > 0
        with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=3) as response:
            assert response.status == 200
            assert response.headers.get_content_type() == "application/json"
            payload = json.loads(response.read().decode("utf-8"))
        parsed = parse_agent_health(
            payload,
            AgentHealthExpectation(instance_id="instance-1"),
        )
        assert parsed.status == "ok"

        with pytest.raises(HTTPError) as missing:
            urlopen(f"http://127.0.0.1:{port}/not-health", timeout=3)
        assert missing.value.code == 404

        request = Request(
            f"http://127.0.0.1:{port}/healthz",
            data=b"{}",
            method="POST",
        )
        with pytest.raises(HTTPError) as posted:
            urlopen(request, timeout=3)
        assert posted.value.code == 405


@pytest.mark.parametrize("host", ["0.0.0.0", "::1", "localhost", "192.168.1.10"])
def test_health_server_rejects_non_exact_ipv4_loopback_bind(host: str) -> None:
    with pytest.raises(ValueError):
        AgentHealthServer(
            _state(),
            config=AgentHealthServerConfig(host=host, port=8765),
        )


def test_health_state_refuses_unproven_service_identity_or_privilege() -> None:
    with pytest.raises(ValueError):
        AgentHealthState(
            instance_id="instance-1",
            agent_version="0.1.0",
            workspace_root=r"C:\HMS-Workspace",
            boot_id="boot-1",
            service_identity=r"NT AUTHORITY\LocalService",
            privilege="non-admin",
        ).to_document()

    with pytest.raises(ValueError):
        AgentHealthState(
            instance_id="instance-1",
            agent_version="0.1.0",
            workspace_root=r"C:\HMS-Workspace",
            boot_id="boot-1",
            service_identity=r"NT SERVICE\HMSAgent",
            privilege="admin",
        ).to_document()
