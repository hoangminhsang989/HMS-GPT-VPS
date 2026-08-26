from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .bridge_oauth_http import require_https_endpoint
from .bridge_oauth_jwt_introspection_capability import (
    BridgeOAuthJwtIntrospectionCapabilityEvidence,
)

_MAX_JWT_BYTES = 256 * 1024
_MAX_JSON_BYTES = 128 * 1024
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_ALLOWED_HEADER_KEYS = frozenset({"alg", "kid", "typ"})
_ALLOWED_PAYLOAD_KEYS = frozenset({"iss", "aud", "iat", "token_introspection"})


class BridgeOAuthJwtIntrospectionResponseError(RuntimeError):
    pass


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in items:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _decode_segment(segment: str, name: str, *, max_bytes: int = _MAX_JSON_BYTES) -> bytes:
    if (
        not isinstance(segment, str)
        or not segment
        or len(segment) > _MAX_JWT_BYTES
        or _SEGMENT_RE.fullmatch(segment) is None
    ):
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} JWT segment is invalid")
    padding_count = (-len(segment)) % 4
    try:
        decoded = base64.urlsafe_b64decode(segment + ("=" * padding_count))
    except Exception as exc:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} JWT segment is not base64url") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != segment:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} JWT segment is non-canonical")
    if not decoded or len(decoded) > max_bytes:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} JWT segment size is invalid")
    return decoded


def _decode_json_segment(segment: str, name: str) -> dict[str, Any]:
    data = _decode_segment(segment, name)
    try:
        raw = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} JWT JSON is invalid") from exc
    if not isinstance(raw, dict):
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} JWT JSON must be an object")
    return raw


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
        raise BridgeOAuthJwtIntrospectionResponseError("JWKS is not canonicalizable") from exc
    return hashlib.sha256(data).hexdigest()


def _require_text(value: object, name: str, *, max_length: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} is invalid")
    return value


def _b64uint(value: object, name: str, *, max_bytes: int) -> int:
    text = _require_text(value, name, max_length=max_bytes * 2)
    decoded = _decode_segment(text, name, max_bytes=max_bytes)
    if len(decoded) > 1 and decoded[0] == 0:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} has a non-minimal integer encoding")
    number = int.from_bytes(decoded, "big")
    if number <= 0:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} must be positive")
    return number


def _b64bytes(value: object, name: str, *, exact_length: int | None = None) -> bytes:
    text = _require_text(value, name, max_length=16384)
    decoded = _decode_segment(text, name, max_bytes=8192)
    if exact_length is not None and len(decoded) != exact_length:
        raise BridgeOAuthJwtIntrospectionResponseError(f"{name} length is invalid")
    return decoded


def _hash_for_alg(alg: str) -> hashes.HashAlgorithm:
    if alg.endswith("256"):
        return hashes.SHA256()
    if alg.endswith("384"):
        return hashes.SHA384()
    if alg.endswith("512"):
        return hashes.SHA512()
    raise BridgeOAuthJwtIntrospectionResponseError("unsupported introspection signing algorithm")


def _select_jwk(
    jwks: Mapping[str, Any],
    *,
    kid: str,
    alg: str,
    evidence: BridgeOAuthJwtIntrospectionCapabilityEvidence,
) -> Mapping[str, Any]:
    if _canonical_sha256(jwks) != evidence.jwks_sha256:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "authorization-server JWKS differs from qualified authority"
        )
    keys = jwks.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 32:
        raise BridgeOAuthJwtIntrospectionResponseError("authorization-server JWKS is invalid")
    matches: list[Mapping[str, Any]] = []
    for key in keys:
        if not isinstance(key, dict):
            raise BridgeOAuthJwtIntrospectionResponseError("authorization-server JWK is invalid")
        if _PRIVATE_JWK_MEMBERS.intersection(key):
            raise BridgeOAuthJwtIntrospectionResponseError(
                "authorization-server JWK unexpectedly contains private material"
            )
        if key.get("kid") == kid:
            matches.append(key)
    if len(matches) != 1:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection kid does not identify exactly one qualified key"
        )
    key = matches[0]
    if key.get("alg") != alg or key.get("use") != "sig":
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection JWK algorithm/use differs from JWT authority"
        )
    key_ops = key.get("key_ops")
    if key_ops is not None and key_ops != ["verify"]:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection JWK key_ops is not exact verify-only authority"
        )
    return key


def _verify_signature(
    signing_input: bytes,
    signature: bytes,
    *,
    alg: str,
    jwk: Mapping[str, Any],
) -> None:
    try:
        if alg.startswith(("RS", "PS")):
            if jwk.get("kty") != "RSA":
                raise BridgeOAuthJwtIntrospectionResponseError("RSA algorithm requires RSA JWK")
            n = _b64uint(jwk.get("n"), "RSA modulus", max_bytes=1024)
            e = _b64uint(jwk.get("e"), "RSA exponent", max_bytes=16)
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            digest = _hash_for_alg(alg)
            if alg.startswith("RS"):
                public_key.verify(signature, signing_input, padding.PKCS1v15(), digest)
            else:
                public_key.verify(
                    signature,
                    signing_input,
                    padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size),
                    digest,
                )
            return

        if alg.startswith("ES"):
            curve_info = {
                "ES256": ("P-256", ec.SECP256R1(), 32),
                "ES384": ("P-384", ec.SECP384R1(), 48),
                "ES512": ("P-521", ec.SECP521R1(), 66),
            }.get(alg)
            if curve_info is None or jwk.get("kty") != "EC":
                raise BridgeOAuthJwtIntrospectionResponseError("EC algorithm requires matching EC JWK")
            expected_curve, curve, coordinate_size = curve_info
            if jwk.get("crv") != expected_curve:
                raise BridgeOAuthJwtIntrospectionResponseError("EC curve differs from JWT algorithm")
            x = int.from_bytes(
                _b64bytes(jwk.get("x"), "EC x", exact_length=coordinate_size),
                "big",
            )
            y = int.from_bytes(
                _b64bytes(jwk.get("y"), "EC y", exact_length=coordinate_size),
                "big",
            )
            if len(signature) != coordinate_size * 2:
                raise BridgeOAuthJwtIntrospectionResponseError("ECDSA JWT signature length is invalid")
            r = int.from_bytes(signature[:coordinate_size], "big")
            s = int.from_bytes(signature[coordinate_size:], "big")
            public_key = ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
            public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(_hash_for_alg(alg)))
            return

        if alg == "EdDSA":
            if jwk.get("kty") != "OKP":
                raise BridgeOAuthJwtIntrospectionResponseError("EdDSA requires OKP JWK")
            crv = jwk.get("crv")
            if crv == "Ed25519":
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(
                    _b64bytes(jwk.get("x"), "Ed25519 x", exact_length=32)
                )
            elif crv == "Ed448":
                public_key = ed448.Ed448PublicKey.from_public_bytes(
                    _b64bytes(jwk.get("x"), "Ed448 x", exact_length=57)
                )
            else:
                raise BridgeOAuthJwtIntrospectionResponseError("unsupported EdDSA curve")
            public_key.verify(signature, signing_input)
            return
    except InvalidSignature as exc:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection JWT signature verification failed"
        ) from exc
    except (ValueError, TypeError) as exc:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection JWK is cryptographically invalid"
        ) from exc
    raise BridgeOAuthJwtIntrospectionResponseError("unsupported introspection signing algorithm")


@dataclass(frozen=True)
class VerifiedRfc9701IntrospectionResponse:
    issuer_url: str
    resource_server_url: str
    issued_at: int
    algorithm: str
    kid: str
    token_introspection: Mapping[str, Any]
    signed_introspection_response_proven: bool = True
    token_specific_client_auth_attestation_proven: bool = False
    token_endpoint_private_key_jwt_exchange_proven: bool = False
    chatgpt_app_oauth_client_proven: bool = False
    chatgpt_ui_origin_proven: bool = False

    def validate(self) -> None:
        require_https_endpoint(self.issuer_url, "issuer_url")
        require_https_endpoint(self.resource_server_url, "resource_server_url")
        if isinstance(self.issued_at, bool) or not isinstance(self.issued_at, int) or self.issued_at <= 0:
            raise BridgeOAuthJwtIntrospectionResponseError("signed introspection issued_at is invalid")
        _require_text(self.algorithm, "signed introspection algorithm", max_length=64)
        _require_text(self.kid, "signed introspection kid", max_length=256)
        if not isinstance(self.token_introspection, Mapping):
            raise BridgeOAuthJwtIntrospectionResponseError("token_introspection must be an object")
        if self.signed_introspection_response_proven is not True:
            raise BridgeOAuthJwtIntrospectionResponseError("signed introspection response proof is false")
        for value, name in (
            (self.token_specific_client_auth_attestation_proven, "token-specific client-auth attestation"),
            (self.token_endpoint_private_key_jwt_exchange_proven, "private_key_jwt exchange"),
            (self.chatgpt_app_oauth_client_proven, "ChatGPT OAuth client"),
            (self.chatgpt_ui_origin_proven, "ChatGPT UI origin"),
        ):
            if value is not False:
                raise BridgeOAuthJwtIntrospectionResponseError(
                    f"signed response verification must not claim {name} proof"
                )


def verify_rfc9701_signed_introspection_response(
    jwt_response: str,
    *,
    evidence: BridgeOAuthJwtIntrospectionCapabilityEvidence,
    jwks: Mapping[str, Any],
    resource_server_url: str,
    now: int,
    max_age_seconds: int = 60,
    future_skew_seconds: int = 5,
) -> VerifiedRfc9701IntrospectionResponse:
    """Verify one RFC 9701 signed introspection response against frozen AS/JWKS authority."""

    if not isinstance(evidence, BridgeOAuthJwtIntrospectionCapabilityEvidence):
        raise TypeError("evidence must be BridgeOAuthJwtIntrospectionCapabilityEvidence")
    evidence.validate()
    resource = require_https_endpoint(resource_server_url, "resource_server_url")
    if isinstance(now, bool) or not isinstance(now, int) or now <= 0:
        raise BridgeOAuthJwtIntrospectionResponseError("verification clock is invalid")
    for value, name, upper in (
        (max_age_seconds, "max_age_seconds", 600),
        (future_skew_seconds, "future_skew_seconds", 60),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= upper:
            raise BridgeOAuthJwtIntrospectionResponseError(f"{name} is invalid")

    if (
        not isinstance(jwt_response, str)
        or not jwt_response
        or jwt_response != jwt_response.strip()
        or len(jwt_response.encode("ascii", errors="ignore")) != len(jwt_response)
        or len(jwt_response) > _MAX_JWT_BYTES
    ):
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection JWT is invalid")
    parts = jwt_response.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection JWT compact shape is invalid")

    header = _decode_json_segment(parts[0], "header")
    if frozenset(header) != _ALLOWED_HEADER_KEYS:
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection JWT header schema is invalid")
    if header.get("typ") != "token-introspection+jwt":
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection JWT typ is invalid")
    alg = _require_text(header.get("alg"), "signed introspection alg", max_length=64)
    if alg not in evidence.signing_algorithms:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection JWT algorithm is outside qualified authority"
        )
    kid = _require_text(header.get("kid"), "signed introspection kid", max_length=256)
    if kid not in evidence.jwks_kids:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection JWT kid is outside qualified authority"
        )

    payload = _decode_json_segment(parts[1], "payload")
    if frozenset(payload) != _ALLOWED_PAYLOAD_KEYS:
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection JWT payload schema is invalid")
    if payload.get("iss") != evidence.issuer_url:
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection issuer differs from authority")
    if payload.get("aud") != resource:
        raise BridgeOAuthJwtIntrospectionResponseError(
            "signed introspection audience differs from resource-server authority"
        )
    iat = payload.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int) or iat <= 0:
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection iat is invalid")
    if iat > now + future_skew_seconds or now - iat > max_age_seconds:
        raise BridgeOAuthJwtIntrospectionResponseError("signed introspection response is stale or future-dated")
    introspection = payload.get("token_introspection")
    if not isinstance(introspection, dict):
        raise BridgeOAuthJwtIntrospectionResponseError("token_introspection claim must be an object")
    if introspection.get("active") is False:
        if frozenset(introspection) != {"active"}:
            raise BridgeOAuthJwtIntrospectionResponseError(
                "inactive token_introspection must contain only active=false"
            )
    elif introspection.get("active") is not True:
        raise BridgeOAuthJwtIntrospectionResponseError("token_introspection active must be exact boolean")

    signature = _decode_segment(parts[2], "signature", max_bytes=8192)
    jwk = _select_jwk(jwks, kid=kid, alg=alg, evidence=evidence)
    _verify_signature(
        f"{parts[0]}.{parts[1]}".encode("ascii"),
        signature,
        alg=alg,
        jwk=jwk,
    )

    verified = VerifiedRfc9701IntrospectionResponse(
        issuer_url=evidence.issuer_url,
        resource_server_url=resource,
        issued_at=iat,
        algorithm=alg,
        kid=kid,
        token_introspection=introspection,
    )
    verified.validate()
    return verified
