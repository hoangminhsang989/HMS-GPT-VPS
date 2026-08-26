import copy

import pytest

from hms_gpt_vps.bridge_oauth_jwt_introspection_capability import (
    BridgeOAuthJwtIntrospectionCapabilityError,
    qualify_rfc9701_signed_introspection_capability_sync,
)

ISSUER = "https://issuer.example.test/tenant"
META = "https://issuer.example.test/.well-known/oauth-authorization-server/tenant"
INTRO = "https://issuer.example.test/oauth/introspect"
JWKS = "https://issuer.example.test/.well-known/jwks.json"


def metadata() -> dict[str, object]:
    return {
        "issuer": ISSUER,
        "introspection_endpoint": INTRO,
        "introspection_endpoint_auth_methods_supported": ["client_secret_basic"],
        "introspection_signing_alg_values_supported": ["PS256", "RS256"],
        "jwks_uri": JWKS,
    }


def jwks() -> dict[str, object]:
    return {
        "keys": [
            {
                "kid": "as-key-1",
                "kty": "RSA",
                "use": "sig",
                "alg": "PS256",
                "n": "abc",
                "e": "AQAB",
            }
        ]
    }


def requester(
    *,
    meta_before: dict[str, object] | None = None,
    meta_after: dict[str, object] | None = None,
    jwks_before: dict[str, object] | None = None,
    jwks_after: dict[str, object] | None = None,
):
    before_meta = copy.deepcopy(meta_before or metadata())
    after_meta = copy.deepcopy(meta_after or meta_before or metadata())
    before_jwks = copy.deepcopy(jwks_before or jwks())
    after_jwks = copy.deepcopy(jwks_after or jwks_before or jwks())
    responses = {
        META: [before_meta, after_meta],
        JWKS: [before_jwks, after_jwks],
    }

    def request(method, url, headers, body, timeout_seconds, max_bytes):
        assert method == "GET"
        assert body is None
        return responses[url].pop(0)

    return request


def test_success_is_capability_only() -> None:
    evidence = qualify_rfc9701_signed_introspection_capability_sync(
        ISSUER,
        json_request=requester(),
    )
    assert evidence.rfc9701_signed_introspection_capability_proven is True
    assert evidence.signed_introspection_response_proven is False
    assert evidence.token_specific_client_auth_attestation_proven is False
    assert evidence.token_endpoint_private_key_jwt_exchange_proven is False
    assert evidence.chatgpt_app_oauth_client_proven is False
    assert evidence.chatgpt_ui_origin_proven is False


def test_weak_or_unknown_signing_algorithm_fails() -> None:
    candidate = metadata()
    candidate["introspection_signing_alg_values_supported"] = ["HS256"]
    with pytest.raises(BridgeOAuthJwtIntrospectionCapabilityError):
        qualify_rfc9701_signed_introspection_capability_sync(
            ISSUER,
            json_request=requester(meta_before=candidate),
        )


def test_required_introspection_auth_method_fails_closed() -> None:
    candidate = metadata()
    candidate["introspection_endpoint_auth_methods_supported"] = ["private_key_jwt"]
    with pytest.raises(BridgeOAuthJwtIntrospectionCapabilityError):
        qualify_rfc9701_signed_introspection_capability_sync(
            ISSUER,
            json_request=requester(meta_before=candidate),
        )


def test_private_jwk_material_fails_closed() -> None:
    candidate = jwks()
    candidate["keys"][0]["d"] = "secret"  # type: ignore[index]
    with pytest.raises(BridgeOAuthJwtIntrospectionCapabilityError):
        qualify_rfc9701_signed_introspection_capability_sync(
            ISSUER,
            json_request=requester(jwks_before=candidate),
        )


def test_no_matching_signing_key_fails_closed() -> None:
    candidate = jwks()
    candidate["keys"][0]["alg"] = "RS512"  # type: ignore[index]
    with pytest.raises(BridgeOAuthJwtIntrospectionCapabilityError):
        qualify_rfc9701_signed_introspection_capability_sync(
            ISSUER,
            json_request=requester(jwks_before=candidate),
        )


def test_metadata_drift_fails_closed() -> None:
    after = metadata()
    after["introspection_signing_alg_values_supported"] = ["RS256"]
    with pytest.raises(BridgeOAuthJwtIntrospectionCapabilityError):
        qualify_rfc9701_signed_introspection_capability_sync(
            ISSUER,
            json_request=requester(meta_before=metadata(), meta_after=after),
        )


def test_jwks_drift_fails_closed() -> None:
    after = jwks()
    after["keys"][0]["kid"] = "as-key-2"  # type: ignore[index]
    with pytest.raises(BridgeOAuthJwtIntrospectionCapabilityError):
        qualify_rfc9701_signed_introspection_capability_sync(
            ISSUER,
            json_request=requester(jwks_before=jwks(), jwks_after=after),
        )
