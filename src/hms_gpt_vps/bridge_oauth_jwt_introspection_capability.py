from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .bridge_oauth_http import (
    DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
    MAX_OAUTH_JSON_BYTES,
    SyncJsonRequest,
    authorization_server_metadata_url,
    request_oauth_json_sync,
    require_https_endpoint,
    require_https_issuer,
    require_oauth_timeout,
)

_ALLOWED_SIGNING_ALGS = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
MAX_INTROSPECTION_JWKS_BYTES = 64 * 1024


class BridgeOAuthJwtIntrospectionCapabilityError(RuntimeError):
    pass


def _require_text(value: object, name: str, *, max_length: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise BridgeOAuthJwtIntrospectionCapabilityError(f"{name} is invalid")
    return value


def _require_unique_string_list(
    value: object,
    name: str,
    *,
    max_items: int = 32,
    max_item_length: int = 128,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > max_items:
        raise BridgeOAuthJwtIntrospectionCapabilityError(f"{name} must be a bounded non-empty list")
    items = tuple(_require_text(item, name, max_length=max_item_length) for item in value)
    if len(set(items)) != len(items):
        raise BridgeOAuthJwtIntrospectionCapabilityError(f"{name} must not contain duplicates")
    return items


def _canonical_sha256(value: object) -> str:
    try:
        data = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BridgeOAuthJwtIntrospectionCapabilityError("authority JSON is not canonicalizable") from exc
    return hashlib.sha256(data).hexdigest()


def _validate_metadata(
    issuer: str,
    raw: Mapping[str, Any],
) -> tuple[str, str, tuple[str, ...]]:
    if raw.get("issuer") != issuer:
        raise BridgeOAuthJwtIntrospectionCapabilityError(
            "authorization-server metadata issuer differs from configured authority"
        )
    introspection_endpoint = require_https_endpoint(
        raw.get("introspection_endpoint"),
        "introspection_endpoint",
    )
    auth_methods = _require_unique_string_list(
        raw.get("introspection_endpoint_auth_methods_supported"),
        "introspection_endpoint_auth_methods_supported",
    )
    if "client_secret_basic" not in auth_methods:
        raise BridgeOAuthJwtIntrospectionCapabilityError(
            "authorization server does not advertise the HMS introspection authentication method"
        )
    signing_algs = _require_unique_string_list(
        raw.get("introspection_signing_alg_values_supported"),
        "introspection_signing_alg_values_supported",
    )
    if any(alg not in _ALLOWED_SIGNING_ALGS for alg in signing_algs):
        raise BridgeOAuthJwtIntrospectionCapabilityError(
            "authorization server advertises an unsupported introspection signing algorithm"
        )
    jwks_uri = require_https_endpoint(raw.get("jwks_uri"), "jwks_uri")
    return introspection_endpoint, jwks_uri, signing_algs


def _validate_public_jwks(
    raw: Mapping[str, Any],
    signing_algs: tuple[str, ...],
) -> tuple[str, ...]:
    keys = raw.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 32:
        raise BridgeOAuthJwtIntrospectionCapabilityError("authorization-server JWKS must be bounded and non-empty")
    supported = frozenset(signing_algs)
    kids: list[str] = []
    matching_key = False
    for key in keys:
        if not isinstance(key, dict):
            raise BridgeOAuthJwtIntrospectionCapabilityError("authorization-server JWKS key must be an object")
        if _PRIVATE_JWK_MEMBERS.intersection(key):
            raise BridgeOAuthJwtIntrospectionCapabilityError(
                "authorization-server JWKS unexpectedly contains private key material"
            )
        kid = _require_text(key.get("kid"), "authorization-server JWKS kid", max_length=256)
        alg = _require_text(key.get("alg"), "authorization-server JWKS alg", max_length=64)
        kty = _require_text(key.get("kty"), "authorization-server JWKS kty", max_length=32)
        if key.get("use") != "sig":
            raise BridgeOAuthJwtIntrospectionCapabilityError(
                "authorization-server JWKS key is not explicitly a signing key"
            )
        if alg in supported:
            if kty == "RSA" and alg.startswith(("RS", "PS")):
                _require_text(key.get("n"), "authorization-server RSA modulus", max_length=8192)
                _require_text(key.get("e"), "authorization-server RSA exponent", max_length=64)
                matching_key = True
            elif kty == "EC" and alg.startswith("ES"):
                _require_text(key.get("crv"), "authorization-server EC curve", max_length=64)
                _require_text(key.get("x"), "authorization-server EC x", max_length=1024)
                _require_text(key.get("y"), "authorization-server EC y", max_length=1024)
                matching_key = True
            elif kty == "OKP" and alg == "EdDSA":
                _require_text(key.get("crv"), "authorization-server OKP curve", max_length=64)
                _require_text(key.get("x"), "authorization-server OKP x", max_length=1024)
                matching_key = True
        kids.append(kid)
    if len(set(kids)) != len(kids):
        raise BridgeOAuthJwtIntrospectionCapabilityError("authorization-server JWKS kid values must be unique")
    if not matching_key:
        raise BridgeOAuthJwtIntrospectionCapabilityError(
            "authorization-server JWKS has no key matching advertised introspection signing algorithms"
        )
    return tuple(kids)


@dataclass(frozen=True)
class BridgeOAuthJwtIntrospectionCapabilityEvidence:
    issuer_url: str
    introspection_endpoint: str
    jwks_uri: str
    signing_algorithms: tuple[str, ...]
    jwks_kids: tuple[str, ...]
    metadata_sha256: str
    jwks_sha256: str
    rfc9701_signed_introspection_capability_proven: bool = True
    signed_introspection_response_proven: bool = False
    token_specific_client_auth_attestation_proven: bool = False
    token_endpoint_private_key_jwt_exchange_proven: bool = False
    chatgpt_app_oauth_client_proven: bool = False
    chatgpt_ui_origin_proven: bool = False

    def validate(self) -> None:
        require_https_issuer(self.issuer_url)
        require_https_endpoint(self.introspection_endpoint, "introspection_endpoint")
        require_https_endpoint(self.jwks_uri, "jwks_uri")
        if not self.signing_algorithms or any(alg not in _ALLOWED_SIGNING_ALGS for alg in self.signing_algorithms):
            raise BridgeOAuthJwtIntrospectionCapabilityError("signed introspection algorithm authority is invalid")
        if len(set(self.signing_algorithms)) != len(self.signing_algorithms):
            raise BridgeOAuthJwtIntrospectionCapabilityError("signed introspection algorithms must be unique")
        if not self.jwks_kids or len(set(self.jwks_kids)) != len(self.jwks_kids):
            raise BridgeOAuthJwtIntrospectionCapabilityError("signed introspection JWKS key identity is invalid")
        for digest in (self.metadata_sha256, self.jwks_sha256):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or digest != digest.lower()
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise BridgeOAuthJwtIntrospectionCapabilityError("signed introspection authority digest is invalid")
        if self.rfc9701_signed_introspection_capability_proven is not True:
            raise BridgeOAuthJwtIntrospectionCapabilityError("RFC 9701 capability proof is false")
        for value, name in (
            (self.signed_introspection_response_proven, "signed introspection response"),
            (self.token_specific_client_auth_attestation_proven, "token-specific client-auth attestation"),
            (self.token_endpoint_private_key_jwt_exchange_proven, "private_key_jwt exchange"),
            (self.chatgpt_app_oauth_client_proven, "ChatGPT OAuth client"),
            (self.chatgpt_ui_origin_proven, "ChatGPT UI origin"),
        ):
            if value is not False:
                raise BridgeOAuthJwtIntrospectionCapabilityError(
                    f"capability qualification must not claim {name} proof"
                )


def qualify_rfc9701_signed_introspection_capability_sync(
    issuer_url: str,
    *,
    json_request: SyncJsonRequest = request_oauth_json_sync,
    timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
) -> BridgeOAuthJwtIntrospectionCapabilityEvidence:
    issuer = require_https_issuer(issuer_url)
    require_oauth_timeout(timeout_seconds)
    if not callable(json_request):
        raise TypeError("json_request must be callable")

    metadata_url = authorization_server_metadata_url(issuer)
    headers = {"Accept": "application/json", "User-Agent": "HMS-GPT-VPS RFC9701 qualification"}

    metadata_before = json_request(
        "GET", metadata_url, headers, None, timeout_seconds, MAX_OAUTH_JSON_BYTES
    )
    introspection_endpoint, jwks_uri, signing_algs = _validate_metadata(issuer, metadata_before)
    jwks_before = json_request(
        "GET", jwks_uri, headers, None, timeout_seconds, MAX_INTROSPECTION_JWKS_BYTES
    )
    kids_before = _validate_public_jwks(jwks_before, signing_algs)

    metadata_after = json_request(
        "GET", metadata_url, headers, None, timeout_seconds, MAX_OAUTH_JSON_BYTES
    )
    introspection_after, jwks_uri_after, signing_algs_after = _validate_metadata(issuer, metadata_after)
    jwks_after = json_request(
        "GET", jwks_uri_after, headers, None, timeout_seconds, MAX_INTROSPECTION_JWKS_BYTES
    )
    kids_after = _validate_public_jwks(jwks_after, signing_algs_after)

    metadata_sha = _canonical_sha256(metadata_before)
    jwks_sha = _canonical_sha256(jwks_before)
    if (
        _canonical_sha256(metadata_after) != metadata_sha
        or introspection_after != introspection_endpoint
        or jwks_uri_after != jwks_uri
        or signing_algs_after != signing_algs
    ):
        raise BridgeOAuthJwtIntrospectionCapabilityError(
            "authorization-server RFC 9701 metadata changed across qualification"
        )
    if _canonical_sha256(jwks_after) != jwks_sha or kids_after != kids_before:
        raise BridgeOAuthJwtIntrospectionCapabilityError(
            "authorization-server JWKS changed across qualification"
        )

    evidence = BridgeOAuthJwtIntrospectionCapabilityEvidence(
        issuer_url=issuer,
        introspection_endpoint=introspection_endpoint,
        jwks_uri=jwks_uri,
        signing_algorithms=signing_algs,
        jwks_kids=kids_before,
        metadata_sha256=metadata_sha,
        jwks_sha256=jwks_sha,
    )
    evidence.validate()
    return evidence
