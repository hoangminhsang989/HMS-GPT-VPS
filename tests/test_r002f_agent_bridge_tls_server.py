from __future__ import annotations

import ssl
from pathlib import Path

import pytest

from hms_gpt_vps.agent_bridge_http_boundary import AgentBridgeHttpBoundary
from hms_gpt_vps.agent_bridge_service import AgentBridgeService
from hms_gpt_vps.agent_bridge_tls_server import (
    AgentBridgeTlsHttpShapeError,
    AgentBridgeTlsServer,
    AgentBridgeTlsServerConfig,
    _AgentBridgeTlsHttpServer,
    _declared_body_length,
    _raw_header_occurrences,
)
from hms_gpt_vps.agent_command_store import AgentCommandStore
from hms_gpt_vps.agent_connection_registry import AgentConnectionRegistry
from hms_gpt_vps.agent_transport_protocol import (
    MAX_AGENT_BODY_BYTES,
    AgentDeviceCredential,
)
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig


INSTANCE_ID = "hms-agent-tls-01"
DEVICE_ID = "device-01"


def build_boundary(tmp_path: Path) -> AgentBridgeHttpBoundary:
    db = tmp_path / "db"
    db.mkdir()
    credential = AgentDeviceCredential(
        instance_id=INSTANCE_ID,
        device_id=DEVICE_ID,
        secret=b"S" * 32,
    )

    def request_resolver(instance_id: str, device_id: str):
        if instance_id != INSTANCE_ID or device_id != DEVICE_ID:
            raise KeyError("unknown Agent")
        return credential

    def command_resolver(instance_id: str):
        if instance_id != INSTANCE_ID:
            raise KeyError("unknown Agent")
        return credential

    return AgentBridgeHttpBoundary(
        AgentBridgeService(
            AgentConnectionRegistry(db / "presence.sqlite3"),
            AgentCommandStore(db / "commands.sqlite3"),
            request_resolver,
            command_resolver,
        )
    )


def server_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def test_config_uses_exact_internal_gateway_and_guest_authority() -> None:
    config = AgentBridgeTlsServerConfig(network=HyperVNetworkConfig())
    config.validate()

    assert config.bind_host == "172.29.240.1"
    assert config.allowed_guest_ipv4 == "172.29.240.10"
    assert config.port == 9443


def test_config_rejects_public_managed_subnet() -> None:
    config = AgentBridgeTlsServerConfig(
        network=HyperVNetworkConfig(
            subnet="203.0.113.0/24",
            gateway="203.0.113.1",
            guest_ipv4="203.0.113.10",
        )
    )
    with pytest.raises(ValueError, match="RFC1918"):
        config.validate()


def test_tls_server_rejects_client_context_and_implicit_minimum(
    tmp_path: Path,
) -> None:
    boundary = build_boundary(tmp_path)
    config = AgentBridgeTlsServerConfig(network=HyperVNetworkConfig())

    with pytest.raises(ValueError, match="PROTOCOL_TLS_SERVER"):
        AgentBridgeTlsServer(
            boundary,
            config,
            ssl.create_default_context(),
        )

    weak = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    weak.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with pytest.raises(ValueError, match="TLS 1.2"):
        AgentBridgeTlsServer(boundary, config, weak)


def test_tls_server_construction_does_not_open_listener(tmp_path: Path) -> None:
    boundary = build_boundary(tmp_path)
    server = AgentBridgeTlsServer(
        boundary,
        AgentBridgeTlsServerConfig(network=HyperVNetworkConfig()),
        server_context(),
    )

    assert server.boundary is boundary
    assert server.bound_address is None


class RawHeaders:
    def raw_items(self):
        return [
            ("Content-Length", "12"),
            ("Authorization", "first"),
            ("authorization", "second"),
        ]


def test_raw_header_occurrences_are_not_folded_by_listener() -> None:
    headers = _raw_header_occurrences(RawHeaders())
    assert headers == (
        ("Content-Length", "12"),
        ("Authorization", "first"),
        ("authorization", "second"),
    )


@pytest.mark.parametrize(
    "headers",
    [
        (),
        (("Content-Length", "1"), ("content-length", "1")),
        (("Content-Length", "01"),),
        (("Content-Length", " 1"),),
        (("Transfer-Encoding", "chunked"), ("Content-Length", "1")),
    ],
)
def test_declared_body_length_rejects_ambiguous_http_framing(
    headers: tuple[tuple[str, str], ...],
) -> None:
    with pytest.raises(AgentBridgeTlsHttpShapeError):
        _declared_body_length(headers)


def test_declared_body_length_rejects_oversize_before_body_read() -> None:
    with pytest.raises(OverflowError):
        _declared_body_length(
            (("Content-Length", str(MAX_AGENT_BODY_BYTES + 1)),)
        )


class FakeRawSocket:
    def __init__(self) -> None:
        self.closed = False
        self.timeout: int | None = None

    def settimeout(self, timeout: int) -> None:
        self.timeout = timeout

    def close(self) -> None:
        self.closed = True


class FakeListeningSocket:
    def __init__(self, raw: FakeRawSocket, address: tuple[str, int]) -> None:
        self.raw = raw
        self.address = address

    def accept(self):
        return self.raw, self.address


class FakeTlsContext:
    def __init__(self) -> None:
        self.calls: list[tuple[object, bool]] = []

    def wrap_socket(self, raw_socket, *, server_side: bool):
        self.calls.append((raw_socket, server_side))
        return "tls-socket"


def bare_http_server(
    *,
    source_ipv4: str,
) -> tuple[_AgentBridgeTlsHttpServer, FakeRawSocket, FakeTlsContext]:
    server = object.__new__(_AgentBridgeTlsHttpServer)
    raw = FakeRawSocket()
    tls = FakeTlsContext()
    server.socket = FakeListeningSocket(raw, (source_ipv4, 49152))
    server.allowed_guest_ipv4 = "172.29.240.10"
    server.request_timeout_seconds = 30
    server.ssl_context = tls
    return server, raw, tls


def test_unapproved_source_is_closed_before_tls_handshake() -> None:
    server, raw, tls = bare_http_server(source_ipv4="172.29.240.11")

    with pytest.raises(PermissionError):
        server.get_request()

    assert raw.closed is True
    assert raw.timeout is None
    assert tls.calls == []


def test_exact_guest_source_gets_timeout_then_tls_wrap() -> None:
    server, raw, tls = bare_http_server(source_ipv4="172.29.240.10")

    wrapped, address = server.get_request()

    assert wrapped == "tls-socket"
    assert address == ("172.29.240.10", 49152)
    assert raw.timeout == 30
    assert tls.calls == [(raw, True)]
