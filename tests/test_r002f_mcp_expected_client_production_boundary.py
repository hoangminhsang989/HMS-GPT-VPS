from __future__ import annotations

import asyncio

import pytest
from mcp.server.auth.provider import AccessToken

from hms_gpt_vps.mcp_bridge_server import (
    HmsMcpAuthenticationError,
    HmsMcpBridgeConfig,
    HmsMcpBridgeError,
    MCP_CONTROL_SCOPE,
    ResourceBoundTokenVerifier,
    principal_from_access_token,
)

ISSUER = "https://issuer.example.test"
RESOURCE = "https://resource.example.test"
EXPECTED = "chatgpt-confidential-client-01"


def config() -> HmsMcpBridgeConfig:
    return HmsMcpBridgeConfig(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
        expected_client_id=EXPECTED,
    )


def token(client_id: str = EXPECTED) -> AccessToken:
    return AccessToken(
        token="opaque",
        client_id=client_id,
        scopes=[MCP_CONTROL_SCOPE],
        expires_at=2_000_000_000,
        resource=RESOURCE,
        subject="user-123",
        claims={"iss": ISSUER, "aud": RESOURCE},
    )


class Upstream:
    def __init__(self, value):
        self.value = value

    async def verify_token(self, raw: str):
        return self.value


def test_resource_bound_verifier_rechecks_exact_expected_client_id() -> None:
    accepted = asyncio.run(
        ResourceBoundTokenVerifier(
            Upstream(token()),
            config(),
            clock=lambda: 1_900_000_000,
        ).verify_token("opaque")
    )
    assert accepted is not None and accepted.client_id == EXPECTED
    rejected = asyncio.run(
        ResourceBoundTokenVerifier(
            Upstream(token("other-client")),
            config(),
            clock=lambda: 1_900_000_000,
        ).verify_token("opaque")
    )
    assert rejected is None


def test_principal_boundary_rejects_client_mismatch_even_after_upstream_verification() -> None:
    principal = principal_from_access_token(token(), config())
    principal.validate()
    with pytest.raises(
        HmsMcpAuthenticationError,
        match="differs from configured authority",
    ):
        principal_from_access_token(token("other-client"), config())


@pytest.mark.parametrize(
    "value",
    ["", " client", "client ", "client\nname", "x" * 513],
)
def test_expected_client_config_grammar_is_strict(value: str) -> None:
    with pytest.raises(HmsMcpBridgeError, match="expected_client_id"):
        HmsMcpBridgeConfig(
            issuer_url=ISSUER,
            resource_server_url=RESOURCE,
            expected_client_id=value,
        ).validate()


def test_unbound_hms_config_remains_compatibility_only() -> None:
    HmsMcpBridgeConfig(
        issuer_url=ISSUER,
        resource_server_url=RESOURCE,
    ).validate()
