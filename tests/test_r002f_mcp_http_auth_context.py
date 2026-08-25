from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.provider import AccessToken

from hms_gpt_vps.mcp_bridge_server import (
    HmsMcpBridgeConfig,
    MCP_CONTROL_SCOPE,
    build_hms_mcp_server,
)
from hms_gpt_vps.principal_pairing_service import PrincipalPairingResult


ISSUER = "https://auth.example.com/"
RESOURCE = "https://hms.example.com/mcp"


class StaticVerifier:
    async def verify_token(self, token: str) -> AccessToken | None:
        if token != "incoming-token":
            return None
        return AccessToken(
            token=token,
            client_id="chatgpt-client",
            scopes=[MCP_CONTROL_SCOPE],
            expires_at=2_000_000_000,
            resource=RESOURCE,
            subject="user-01",
            claims={"iss": ISSUER},
        )


class PairOnlyControl:
    def __init__(self) -> None:
        self.principal = None
        self.link = None

    def pair_vps(self, principal, pairing_link: str):  # type: ignore[no-untyped-def]
        self.principal = principal
        self.link = pairing_link
        return PrincipalPairingResult(
            instance_id="hms-01",
            session_id="session-01",
            scopes=("workspace.read", "workspace.write"),
            expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )

    def read_file(self, principal, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("read_file is not part of this pairing auth test")

    def write_file(self, principal, **kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("write_file is not part of this pairing auth test")


def test_streamable_http_bearer_auth_reaches_sync_pair_tool() -> None:
    control = PairOnlyControl()
    server = build_hms_mcp_server(
        control,
        StaticVerifier(),
        HmsMcpBridgeConfig(
            issuer_url=ISSUER,
            resource_server_url=RESOURCE,
        ),
    )

    async def scenario() -> None:
        url = "http://127.0.0.1:8765/mcp"
        transport = httpx2.ASGITransport(app=server.streamable_http_app())
        async with server.session_manager.run():
            async with (
                httpx2.AsyncClient(
                    transport=transport,
                    base_url=url,
                    headers={"Authorization": "Bearer incoming-token"},
                ) as http_client,
                Client(
                    streamable_http_client(
                        url,
                        http_client=http_client,
                    )
                ) as client,
            ):
                result = await client.call_tool(
                    "pair_vps",
                    {"pairing_link": "https://bridge.example/pair/pair-01#secret"},
                )
                assert result.is_error is False

    asyncio.run(scenario())
    assert control.principal is not None
    assert control.link == "https://bridge.example/pair/pair-01#secret"
    assert "incoming-token" not in repr(control.principal)
    assert "user-01" not in repr(control.principal)


def test_streamable_http_rejects_missing_bearer_before_tool_dispatch() -> None:
    control = PairOnlyControl()
    server = build_hms_mcp_server(
        control,
        StaticVerifier(),
        HmsMcpBridgeConfig(
            issuer_url=ISSUER,
            resource_server_url=RESOURCE,
        ),
    )

    async def scenario() -> None:
        transport = httpx2.ASGITransport(app=server.streamable_http_app())
        async with server.session_manager.run():
            async with httpx2.AsyncClient(
                transport=transport,
                base_url="http://127.0.0.1:8765",
            ) as http_client:
                response = await http_client.post("/mcp", json={})
                assert response.status_code == 401

    asyncio.run(scenario())
    assert control.principal is None
