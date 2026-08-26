from __future__ import annotations

import asyncio

import pytest

from hms_gpt_vps.bridge_oauth_http import BridgeOAuthAuthorizationServerMetadata
from hms_gpt_vps.bridge_oauth_introspection_credential import BridgeOAuthIntrospectionCredential
from hms_gpt_vps.bridge_oauth_introspection_verifier import (
    BridgeOAuthIntrospectionTokenVerifier,
    BridgeOAuthIntrospectionVerifierError,
    build_bridge_oauth_introspection_verifier_sync,
    require_oauth_token_client_id,
)

ISSUER = "https://issuer.example.test/tenant"
RESOURCE = "https://bridge.example.test/mcp"
ENDPOINT = "https://issuer.example.test/oauth/introspect"
EXPECTED = "chatgpt-confidential-client-01"


def credential() -> BridgeOAuthIntrospectionCredential:
    return BridgeOAuthIntrospectionCredential(
        issuer_url=ISSUER,
        client_id="hms-introspection-client",
        client_secret="hms-introspection-secret",
    )


def active(client_id: str = EXPECTED) -> dict[str, object]:
    return {
        "active": True,
        "client_id": client_id,
        "sub": "user-123",
        "scope": "openid hms.vps.control",
        "aud": RESOURCE,
        "exp": 2_000_000_000,
        "token_type": "Bearer",
    }


def verifier_for(response: dict[str, object], *, expected: str | None = EXPECTED):
    async def request(*args):
        return response

    return BridgeOAuthIntrospectionTokenVerifier(
        credential(),
        BridgeOAuthAuthorizationServerMetadata(ISSUER, ENDPOINT),
        RESOURCE,
        expected_client_id=expected,
        json_request=request,
        clock=lambda: 1_900_000_000,
    )


def test_expected_client_id_is_case_sensitive_and_fail_closed() -> None:
    accepted = asyncio.run(verifier_for(active()).verify_token("opaque"))
    assert accepted is not None and accepted.client_id == EXPECTED
    assert asyncio.run(verifier_for(active("other-client")).verify_token("opaque")) is None
    assert asyncio.run(verifier_for(active(EXPECTED.upper())).verify_token("opaque")) is None


def test_unbound_mode_remains_only_for_nonproduction_compatibility() -> None:
    token = asyncio.run(verifier_for(active("legacy-client"), expected=None).verify_token("opaque"))
    assert token is not None and token.client_id == "legacy-client"


def test_expected_client_id_grammar_is_strict() -> None:
    assert require_oauth_token_client_id(EXPECTED) == EXPECTED
    for value in (None, "", " client", "client ", "client\nname", "x" * 513):
        with pytest.raises(BridgeOAuthIntrospectionVerifierError):
            require_oauth_token_client_id(value)


def test_sync_builder_preserves_expected_client_authority() -> None:
    def discovery(*args):
        return {
            "issuer": ISSUER,
            "introspection_endpoint": ENDPOINT,
            "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
        }

    built = build_bridge_oauth_introspection_verifier_sync(
        credential(),
        RESOURCE,
        expected_client_id=EXPECTED,
        discovery_request=discovery,
        json_request=lambda *args: None,
    )
    assert built.expected_client_id == EXPECTED
