from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from hms_gpt_vps.bridge_oauth_jwt_introspection_capability import (
    BridgeOAuthJwtIntrospectionCapabilityEvidence,
)
from hms_gpt_vps.bridge_oauth_jwt_introspection_response import (
    BridgeOAuthJwtIntrospectionResponseError,
    verify_rfc9701_signed_introspection_response,
)

ISSUER = "https://issuer.example.test/tenant"
INTRO = "https://issuer.example.test/oauth/introspect"
JWKS_URI = "https://issuer.example.test/.well-known/jwks.json"
RESOURCE = "https://bridge.example.test/mcp"
NOW = 2_000_000_000


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64uint(value: int) -> str:
    return b64u(value.to_bytes((value.bit_length() + 7) // 8, "big"))


@pytest.fixture()
def authority():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private_key.public_key().public_numbers()
    jwks = {
        "keys": [
            {
                "kid": "as-key-1",
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": b64uint(public.n),
                "e": b64uint(public.e),
            }
        ]
    }
    jwks_sha256 = hashlib.sha256(
        json.dumps(
            jwks,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    evidence = BridgeOAuthJwtIntrospectionCapabilityEvidence(
        issuer_url=ISSUER,
        introspection_endpoint=INTRO,
        jwks_uri=JWKS_URI,
        signing_algorithms=("RS256",),
        jwks_kids=("as-key-1",),
        metadata_sha256="a" * 64,
        jwks_sha256=jwks_sha256,
    )
    return private_key, jwks, evidence


def make_jwt(
    private_key,
    *,
    typ: str = "token-introspection+jwt",
    issuer: str = ISSUER,
    audience: str = RESOURCE,
    issued_at: int = NOW,
    token_introspection: dict[str, object] | None = None,
) -> str:
    header = {"alg": "RS256", "kid": "as-key-1", "typ": typ}
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": issued_at,
        "token_introspection": token_introspection
        or {
            "active": True,
            "client_id": "https://chatgpt.com/oauth/hms/client.json",
            "sub": "user-123",
            "scope": "hms.vps.control",
            "aud": RESOURCE,
        },
    }
    encoded_header = b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded_header}.{encoded_payload}.{b64u(signature)}"


def verify(jwt_response: str, authority):
    _, jwks, evidence = authority
    return verify_rfc9701_signed_introspection_response(
        jwt_response,
        evidence=evidence,
        jwks=jwks,
        resource_server_url=RESOURCE,
        now=NOW,
    )


def test_valid_signed_response_proves_only_signed_envelope(authority) -> None:
    private_key, _, _ = authority
    verified = verify(make_jwt(private_key), authority)
    assert verified.signed_introspection_response_proven is True
    assert verified.token_specific_client_auth_attestation_proven is False
    assert verified.token_endpoint_private_key_jwt_exchange_proven is False
    assert verified.chatgpt_app_oauth_client_proven is False
    assert verified.chatgpt_ui_origin_proven is False
    assert verified.token_introspection["active"] is True


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("typ", "JWT"),
        ("issuer", "https://other.example.test"),
        ("audience", "https://other.example.test/mcp"),
        ("issued_at", NOW - 61),
    ],
)
def test_envelope_authority_drift_fails_closed(authority, field: str, value: object) -> None:
    private_key, _, _ = authority
    kwargs = {field: value}
    with pytest.raises(BridgeOAuthJwtIntrospectionResponseError):
        verify(make_jwt(private_key, **kwargs), authority)


def test_signature_tamper_fails_closed(authority) -> None:
    private_key, _, _ = authority
    jwt_response = make_jwt(private_key)
    header, payload, signature = jwt_response.split(".")
    tampered_payload = payload[:-1] + ("A" if payload[-1] != "A" else "B")
    with pytest.raises(BridgeOAuthJwtIntrospectionResponseError):
        verify(f"{header}.{tampered_payload}.{signature}", authority)


def test_qualified_jwks_digest_drift_fails_closed(authority) -> None:
    private_key, jwks, evidence = authority
    jwt_response = make_jwt(private_key)
    drifted = json.loads(json.dumps(jwks))
    drifted["keys"][0]["kid"] = "as-key-2"
    with pytest.raises(BridgeOAuthJwtIntrospectionResponseError):
        verify_rfc9701_signed_introspection_response(
            jwt_response,
            evidence=evidence,
            jwks=drifted,
            resource_server_url=RESOURCE,
            now=NOW,
        )


def test_inactive_response_must_contain_only_active_false(authority) -> None:
    private_key, _, _ = authority
    with pytest.raises(BridgeOAuthJwtIntrospectionResponseError):
        verify(
            make_jwt(
                private_key,
                token_introspection={"active": False, "client_id": "must-not-be-here"},
            ),
            authority,
        )


def test_inactive_response_exact_shape_is_accepted(authority) -> None:
    private_key, _, _ = authority
    verified = verify(
        make_jwt(private_key, token_introspection={"active": False}),
        authority,
    )
    assert verified.token_introspection == {"active": False}


def test_top_level_claim_extension_is_rejected_fail_closed(authority) -> None:
    private_key, jwks, evidence = authority
    header = {"alg": "RS256", "kid": "as-key-1", "typ": "token-introspection+jwt"}
    payload = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "iat": NOW,
        "jti": "unexpected-top-level-extension",
        "token_introspection": {"active": False},
    }
    h = b64u(json.dumps(header, separators=(",", ":")).encode())
    p = b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = private_key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    with pytest.raises(BridgeOAuthJwtIntrospectionResponseError):
        verify_rfc9701_signed_introspection_response(
            f"{h}.{p}.{b64u(sig)}",
            evidence=evidence,
            jwks=jwks,
            resource_server_url=RESOURCE,
            now=NOW,
        )
