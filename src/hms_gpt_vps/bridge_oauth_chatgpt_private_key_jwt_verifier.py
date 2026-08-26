from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any, Callable

from mcp.server.auth.provider import AccessToken

from .bridge_oauth_http import (
    DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
    JsonRequest,
    SyncJsonRequest,
    discover_bridge_oauth_authorization_server_sync,
    request_oauth_json,
    request_oauth_json_sync,
)
from .bridge_oauth_introspection_credential import BridgeOAuthIntrospectionCredential
from .bridge_oauth_introspection_verifier import BridgeOAuthIntrospectionTokenVerifier
from .chatgpt_cimd_authority import (
    CHATGPT_CIMD_JWKS_URI,
    qualify_chatgpt_cimd_authority_sync,
    require_chatgpt_cimd_client_id,
)

_PRIVATE_KEY_JWT = "private_key_jwt"
_ATTESTATION_FIELD = "client_auth_attestation"
_ATTESTATION_KEYS = frozenset({"verified", "method", "client_id", "jwks_uri", "kid"})
_MAX_KIDS = 32


class BridgeOAuthChatGptClientAuthError(RuntimeError):
    pass


def _require_kid(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(char) < 0x21 or ord(char) > 0x7E for char in value)
    ):
        raise BridgeOAuthChatGptClientAuthError("ChatGPT client assertion kid is invalid")
    return value


def _require_jwks_kids(values: Collection[str]) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Collection):
        raise BridgeOAuthChatGptClientAuthError("ChatGPT JWKS kid authority is invalid")
    kids = tuple(_require_kid(value) for value in values)
    if not kids or len(kids) > _MAX_KIDS or len(set(kids)) != len(kids):
        raise BridgeOAuthChatGptClientAuthError("ChatGPT JWKS kid authority is invalid")
    return frozenset(kids)


def validate_chatgpt_private_key_jwt_introspection_extension(
    raw: Mapping[str, Any],
    *,
    expected_client_id: str,
    expected_jwks_kids: Collection[str],
) -> tuple[str, str]:
    """Validate issuer-side token-specific client-auth evidence from one introspection response."""

    client_id = require_chatgpt_cimd_client_id(expected_client_id)
    kids = _require_jwks_kids(expected_jwks_kids)
    attestation = raw.get(_ATTESTATION_FIELD)
    if not isinstance(attestation, dict) or frozenset(attestation) != _ATTESTATION_KEYS:
        raise BridgeOAuthChatGptClientAuthError(
            "issuer token-specific client-auth attestation schema is invalid"
        )
    if attestation.get("verified") is not True:
        raise BridgeOAuthChatGptClientAuthError(
            "issuer did not attest successful client authentication"
        )
    if attestation.get("method") != _PRIVATE_KEY_JWT:
        raise BridgeOAuthChatGptClientAuthError(
            "issuer client authentication method is not private_key_jwt"
        )
    if attestation.get("client_id") != client_id:
        raise BridgeOAuthChatGptClientAuthError(
            "issuer client-auth attestation client_id differs from authority"
        )
    if attestation.get("jwks_uri") != CHATGPT_CIMD_JWKS_URI:
        raise BridgeOAuthChatGptClientAuthError(
            "issuer client-auth attestation JWKS authority differs from ChatGPT"
        )
    kid = _require_kid(attestation.get("kid"))
    if kid not in kids:
        raise BridgeOAuthChatGptClientAuthError(
            "issuer client-auth attestation signing key is outside qualified ChatGPT JWKS"
        )
    return _PRIVATE_KEY_JWT, kid


class BridgeOAuthChatGptPrivateKeyJwtVerifier(BridgeOAuthIntrospectionTokenVerifier):
    """RFC 7662 verifier that additionally requires token-specific ChatGPT client-auth evidence."""

    def __init__(
        self,
        credential: BridgeOAuthIntrospectionCredential,
        metadata,
        resource_server_url: str,
        *,
        expected_client_id: str,
        expected_jwks_kids: Collection[str],
        json_request: JsonRequest = request_oauth_json,
        clock: Callable[[], int] | None = None,
        timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
    ) -> None:
        client_id = require_chatgpt_cimd_client_id(expected_client_id)
        kids = _require_jwks_kids(expected_jwks_kids)
        super().__init__(
            credential,
            metadata,
            resource_server_url,
            expected_client_id=client_id,
            json_request=json_request,
            clock=clock,
            timeout_seconds=timeout_seconds,
        )
        self.expected_jwks_kids = kids

    def _map_active(self, token: str, raw: Mapping[str, Any]) -> AccessToken | None:
        base = super()._map_active(token, raw)
        if base is None:
            return None
        try:
            method, kid = validate_chatgpt_private_key_jwt_introspection_extension(
                raw,
                expected_client_id=self.expected_client_id,
                expected_jwks_kids=self.expected_jwks_kids,
            )
        except BridgeOAuthChatGptClientAuthError:
            return None

        claims = dict(base.claims) if isinstance(base.claims, dict) else {}
        claims.update(
            {
                "client_auth_method": method,
                "client_auth_jwks_uri": CHATGPT_CIMD_JWKS_URI,
                "client_auth_kid": kid,
                "client_auth_attestation_schema_version": 1,
            }
        )
        return AccessToken(
            token=base.token,
            client_id=base.client_id,
            scopes=list(base.scopes),
            expires_at=base.expires_at,
            resource=base.resource,
            subject=base.subject,
            claims=claims,
        )


def build_bridge_oauth_chatgpt_private_key_jwt_verifier_sync(
    credential: BridgeOAuthIntrospectionCredential,
    resource_server_url: str,
    *,
    expected_client_id: str,
    discovery_request: SyncJsonRequest = request_oauth_json_sync,
    cimd_request: SyncJsonRequest = request_oauth_json_sync,
    json_request: JsonRequest = request_oauth_json,
    timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
) -> BridgeOAuthChatGptPrivateKeyJwtVerifier:
    """Build only after fresh ChatGPT CIMD/JWKS qualification and issuer discovery."""

    if not isinstance(credential, BridgeOAuthIntrospectionCredential):
        raise TypeError("credential must be a BridgeOAuthIntrospectionCredential")
    credential.validate()
    client_id = require_chatgpt_cimd_client_id(expected_client_id)

    cimd = qualify_chatgpt_cimd_authority_sync(
        credential.issuer_url,
        client_id,
        json_request=cimd_request,
        timeout_seconds=timeout_seconds,
    )
    cimd.validate()
    metadata = discover_bridge_oauth_authorization_server_sync(
        credential.issuer_url,
        json_request=discovery_request,
        timeout_seconds=timeout_seconds,
    )
    if metadata.issuer_url != cimd.issuer_url:
        raise BridgeOAuthChatGptClientAuthError(
            "OAuth introspection issuer differs from qualified ChatGPT CIMD authority"
        )

    return BridgeOAuthChatGptPrivateKeyJwtVerifier(
        credential,
        metadata,
        resource_server_url,
        expected_client_id=client_id,
        expected_jwks_kids=cimd.jwks_kids,
        json_request=json_request,
        timeout_seconds=timeout_seconds,
    )
