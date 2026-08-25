from __future__ import annotations

import asyncio
import base64
from urllib.parse import parse_qs

from hms_gpt_vps.bridge_oauth_http import BridgeOAuthAuthorizationServerMetadata
from hms_gpt_vps.bridge_oauth_introspection_credential import BridgeOAuthIntrospectionCredential
from hms_gpt_vps.bridge_oauth_introspection_verifier import (
    BridgeOAuthIntrospectionTokenVerifier,
    build_bridge_oauth_introspection_verifier_sync,
)

ISSUER = "https://issuer.example.test/tenant"
RESOURCE = "https://bridge.example.test/mcp"
ENDPOINT = "https://issuer.example.test/oauth/introspect"


def _credential() -> BridgeOAuthIntrospectionCredential:
    return BridgeOAuthIntrospectionCredential(issuer_url=ISSUER, client_id="resource:id with space", client_secret="secret:value with space")


def _active(**overrides):
    raw = {"active": True, "client_id": "chatgpt-client", "sub": "user-123", "scope": "openid hms.vps.control", "aud": RESOURCE, "exp": 2_000_000_000, "token_type": "Bearer"}
    raw.update(overrides)
    return raw


def test_verifier_maps_active_resource_bound_token_and_uses_basic_auth() -> None:
    observed = {}

    async def request(method, url, headers, body, timeout, max_bytes):
        observed.update(method=method, headers=dict(headers), body=body)
        return _active()

    verifier = BridgeOAuthIntrospectionTokenVerifier(_credential(), BridgeOAuthAuthorizationServerMetadata(ISSUER, ENDPOINT), RESOURCE, json_request=request, clock=lambda: 1_900_000_000)
    token = asyncio.run(verifier.verify_token("opaque-access-token"))
    assert token is not None and token.client_id == "chatgpt-client" and token.subject == "user-123" and token.resource == RESOURCE
    assert token.scopes == ["openid", "hms.vps.control"] and token.claims == {"iss": ISSUER, "aud": RESOURCE}
    assert parse_qs(observed["body"].decode("ascii")) == {"token": ["opaque-access-token"], "token_type_hint": ["access_token"]}
    decoded = base64.b64decode(observed["headers"]["Authorization"].removeprefix("Basic ")).decode("utf-8")
    assert decoded == "resource%3Aid+with+space:secret%3Avalue+with+space" and b"secret:value" not in observed["body"]


def test_verifier_rejects_wrong_authority_and_bad_bearer_grammar() -> None:
    for response in [_active(scope="openid"), _active(aud="https://other.example.test/mcp"), _active(nbf=1_900_000_001), _active(active=False)]:
        async def request(*args, response=response):
            return response
        verifier = BridgeOAuthIntrospectionTokenVerifier(_credential(), BridgeOAuthAuthorizationServerMetadata(ISSUER, ENDPOINT), RESOURCE, json_request=request, clock=lambda: 1_900_000_000)
        assert asyncio.run(verifier.verify_token("opaque")) is None
    calls = []

    async def should_not_call(*args):
        calls.append(True)
        return _active()

    verifier = BridgeOAuthIntrospectionTokenVerifier(_credential(), BridgeOAuthAuthorizationServerMetadata(ISSUER, ENDPOINT), RESOURCE, json_request=should_not_call)
    assert asyncio.run(verifier.verify_token("token with spaces")) is None
    assert asyncio.run(verifier.verify_token("unicode-☃")) is None and calls == []


def test_verifier_fails_closed_on_network_error() -> None:
    async def fail(*args):
        raise OSError("offline")

    verifier = BridgeOAuthIntrospectionTokenVerifier(_credential(), BridgeOAuthAuthorizationServerMetadata(ISSUER, ENDPOINT), RESOURCE, json_request=fail)
    assert asyncio.run(verifier.verify_token("opaque")) is None


def test_sync_builder_discovers_before_publishing_verifier() -> None:
    events = []

    def discovery(*args):
        events.append("discovery")
        return {"issuer": ISSUER, "introspection_endpoint": ENDPOINT, "introspection_endpoint_auth_methods_supported": ["client_secret_basic"]}

    verifier = build_bridge_oauth_introspection_verifier_sync(_credential(), RESOURCE, discovery_request=discovery, json_request=lambda *args: None)
    assert isinstance(verifier, BridgeOAuthIntrospectionTokenVerifier) and events == ["discovery"]
