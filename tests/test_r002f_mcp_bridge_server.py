from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

import hms_gpt_vps.mcp_bridge_server as bridge_mcp
from hms_gpt_vps.mcp_bridge_server import (
    HmsMcpAuthenticationError,
    HmsMcpBridgeConfig,
    HmsMcpBridgeError,
    HmsMcpToolAdapter,
    HmsMcpToolError,
    MCP_CONTROL_SCOPE,
    ResourceBoundTokenVerifier,
    build_hms_mcp_server,
    principal_from_access_token,
    run_loopback_mcp_server,
)
from hms_gpt_vps.principal_agent_control_service import (
    PrincipalControlState,
    PrincipalControlStatus,
)
from hms_gpt_vps.principal_pairing_service import (
    PrincipalPairingRejectedError,
    PrincipalPairingResult,
)
from mcp.server import MCPServer
from mcp.server.auth.provider import AccessToken


ISSUER = "https://auth.example.com/"
RESOURCE = "https://hms.example.com/mcp"
NOW = datetime(2026, 8, 25, 6, 30, tzinfo=timezone.utc)


def config() -> HmsMcpBridgeConfig:
    return HmsMcpBridgeConfig(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
    )


def access_token(
    *,
    client_id: str = "chatgpt-client",
    subject: str | None = "user-01",
    resource: str | None = RESOURCE,
    issuer: str = ISSUER,
    scopes: list[str] | None = None,
    expires_at: int | None = 2_000_000_000,
) -> AccessToken:
    return AccessToken(
        token="raw-oauth-secret",
        client_id=client_id,
        scopes=[MCP_CONTROL_SCOPE] if scopes is None else scopes,
        expires_at=expires_at,
        resource=resource,
        subject=subject,
        claims={"iss": issuer},
    )


class StaticVerifier:
    def __init__(self, value: AccessToken | None) -> None:
        self.value = value

    async def verify_token(self, token: str) -> AccessToken | None:
        assert token == "incoming"
        return self.value


class RaisingVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        raise RuntimeError("sensitive verifier failure")


class FakeControl:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def pair_vps(self, principal, pairing_link: str):  # type: ignore[no-untyped-def]
        self.calls.append(("pair", principal))
        return PrincipalPairingResult(
            instance_id="hms-01",
            session_id="session-01",
            scopes=("workspace.read", "workspace.write"),
            expires_at=NOW,
        )

    def read_file(self, principal, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("read", principal))
        return PrincipalControlStatus(
            instance_id=kwargs["instance_id"],
            request_id=kwargs["request_id"],
            state=PrincipalControlState.PENDING,
        )

    def write_file(self, principal, **kwargs):  # type: ignore[no-untyped-def]
        self.calls.append(("write", principal))
        return PrincipalControlStatus(
            instance_id=kwargs["instance_id"],
            request_id=kwargs["request_id"],
            state=PrincipalControlState.PENDING,
        )


def test_resource_bound_verifier_rejects_wrong_authority_and_upstream_failure() -> None:
    cfg = config()
    assert asyncio.run(
        ResourceBoundTokenVerifier(
            StaticVerifier(access_token()),
            cfg,
            clock=lambda: 1_900_000_000,
        ).verify_token("incoming")
    ) is not None

    rejected = [
        access_token(resource="https://other.example/mcp"),
        access_token(issuer="https://wrong.example/"),
        access_token(subject=None),
        access_token(scopes=["other.scope"]),
        access_token(expires_at=1_800_000_000),
    ]
    for candidate in rejected:
        assert asyncio.run(
            ResourceBoundTokenVerifier(
                StaticVerifier(candidate),
                cfg,
                clock=lambda: 1_900_000_000,
            ).verify_token("incoming")
        ) is None

    assert asyncio.run(
        ResourceBoundTokenVerifier(
            RaisingVerifier(),
            cfg,
            clock=lambda: 1_900_000_000,
        ).verify_token("incoming")
    ) is None


def test_principal_is_derived_only_from_trusted_token_identity() -> None:
    cfg = config()
    first = principal_from_access_token(access_token(), cfg)
    same = principal_from_access_token(access_token(), cfg)
    other = principal_from_access_token(access_token(subject="user-02"), cfg)

    assert first == same
    assert first != other
    assert "user-01" not in repr(first)
    assert "raw-oauth-secret" not in repr(first)


def test_adapter_uses_auth_context_and_never_accepts_principal_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeControl()
    adapter = HmsMcpToolAdapter(fake, config())
    monkeypatch.setattr(bridge_mcp, "get_access_token", lambda: access_token())

    paired = adapter.pair_vps("https://bridge.example/pair/pair-01#token")
    read = adapter.read_file("hms-01", "req-read-01", "README.md")
    written = adapter.write_file(
        "hms-01",
        "req-write-01",
        "created.txt",
        "hello",
    )

    assert paired["instance_id"] == "hms-01"
    assert read["state"] == "pending"
    assert written["state"] == "pending"
    assert [name for name, _ in fake.calls] == ["pair", "read", "write"]
    principal_hashes = [principal.sha256() for _, principal in fake.calls]
    assert len(set(principal_hashes)) == 1


def test_adapter_rejects_missing_auth_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = HmsMcpToolAdapter(FakeControl(), config())
    monkeypatch.setattr(bridge_mcp, "get_access_token", lambda: None)
    with pytest.raises(HmsMcpAuthenticationError, match="principal is unavailable"):
        adapter.read_file("hms-01", "req-read-01", "README.md")


def test_pairing_error_is_sanitized_without_echoing_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class RejectingControl(FakeControl):
        def pair_vps(self, principal, pairing_link: str):  # type: ignore[no-untyped-def]
            raise PrincipalPairingRejectedError("do not expose pairing-link-secret")

    adapter = HmsMcpToolAdapter(RejectingControl(), config())
    monkeypatch.setattr(bridge_mcp, "get_access_token", lambda: access_token())
    with pytest.raises(HmsMcpToolError) as captured:
        adapter.pair_vps("pairing-link-secret")
    assert str(captured.value) == "pairing_rejected"
    assert "pairing-link-secret" not in str(captured.value)


def test_build_server_uses_mcp_v2_and_http_auth_contract() -> None:
    server = build_hms_mcp_server(
        FakeControl(),
        StaticVerifier(access_token()),
        config(),
    )
    assert isinstance(server, MCPServer)


def test_loopback_runner_cannot_bind_public_interface() -> None:
    class FakeServer:
        def __init__(self) -> None:
            self.kwargs = None

        def run(self, **kwargs):  # type: ignore[no-untyped-def]
            self.kwargs = kwargs

    fake = FakeServer()
    run_loopback_mcp_server(fake, config())  # type: ignore[arg-type]
    assert fake.kwargs is not None
    assert fake.kwargs["transport"] == "streamable-http"
    assert fake.kwargs["host"] == "127.0.0.1"
    assert fake.kwargs["streamable_http_path"] == "/mcp"
    assert fake.kwargs["stateless_http"] is True
    assert fake.kwargs["json_response"] is True


@pytest.mark.parametrize(
    "cfg",
    [
        HmsMcpBridgeConfig(
            issuer_url="http://auth.example.com/",
            resource_server_url=RESOURCE,
        ),
        HmsMcpBridgeConfig(
            issuer_url=ISSUER,
            resource_server_url="http://127.0.0.1:8765/mcp",
        ),
        HmsMcpBridgeConfig(
            issuer_url=ISSUER,
            resource_server_url=RESOURCE,
            port=True,  # type: ignore[arg-type]
        ),
    ],
)
def test_config_rejects_non_https_authority_and_bool_port(cfg: HmsMcpBridgeConfig) -> None:
    with pytest.raises(HmsMcpBridgeError):
        cfg.validate()
