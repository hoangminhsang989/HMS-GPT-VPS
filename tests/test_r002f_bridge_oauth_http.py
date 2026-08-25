from __future__ import annotations

import pytest

from hms_gpt_vps.bridge_oauth_http import (
    BridgeOAuthDiscoveryError,
    authorization_server_metadata_url,
    discover_bridge_oauth_authorization_server_sync,
)

ISSUER = "https://issuer.example.test/tenant"
ENDPOINT = "https://issuer.example.test/oauth/introspect"


def test_metadata_url_inserts_well_known_before_issuer_path() -> None:
    assert authorization_server_metadata_url(ISSUER) == "https://issuer.example.test/.well-known/oauth-authorization-server/tenant"
    assert authorization_server_metadata_url("https://issuer.example.test/") == "https://issuer.example.test/.well-known/oauth-authorization-server"


def test_discovery_requires_exact_issuer_and_explicit_basic_auth_support() -> None:
    calls = []

    def request(method, url, headers, body, timeout, max_bytes):
        calls.append((method, url))
        return {"issuer": ISSUER, "introspection_endpoint": ENDPOINT, "introspection_endpoint_auth_methods_supported": ["client_secret_basic"]}

    metadata = discover_bridge_oauth_authorization_server_sync(ISSUER, json_request=request)
    assert metadata.introspection_endpoint == ENDPOINT and calls[0][0] == "GET"
    with pytest.raises(BridgeOAuthDiscoveryError, match="issuer differs"):
        discover_bridge_oauth_authorization_server_sync(ISSUER, json_request=lambda *args: {"issuer": "https://attacker.example.test", "introspection_endpoint": ENDPOINT, "introspection_endpoint_auth_methods_supported": ["client_secret_basic"]})
    with pytest.raises(BridgeOAuthDiscoveryError, match="explicitly advertise"):
        discover_bridge_oauth_authorization_server_sync(ISSUER, json_request=lambda *args: {"issuer": ISSUER, "introspection_endpoint": ENDPOINT, "introspection_endpoint_auth_methods_supported": ["private_key_jwt"]})
