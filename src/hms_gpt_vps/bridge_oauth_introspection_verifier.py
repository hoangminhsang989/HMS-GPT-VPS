from __future__ import annotations

import base64
import re
import time
from typing import Any, Callable, Mapping
from urllib.parse import quote_plus, urlencode

from mcp.server.auth.provider import AccessToken, TokenVerifier

from .bridge_oauth_http import (
    BridgeOAuthAuthorizationServerMetadata,
    DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
    JsonRequest,
    MAX_OAUTH_JSON_BYTES,
    SyncJsonRequest,
    discover_bridge_oauth_authorization_server,
    discover_bridge_oauth_authorization_server_sync,
    request_oauth_json,
    request_oauth_json_sync,
    require_https_endpoint,
    require_oauth_timeout,
)
from .bridge_oauth_introspection_credential import BridgeOAuthIntrospectionCredential
from .mcp_bridge_server import MCP_CONTROL_SCOPE


_MAX_BEARER_TOKEN_BYTES = 16 * 1024
_BEARER_TOKEN_RE = re.compile(r"^[A-Za-z0-9\-._~+/]+={0,}$")


class BridgeOAuthIntrospectionVerifierError(RuntimeError):
    pass


def _basic_header(client_id: str, client_secret: str) -> str:
    raw = f"{quote_plus(client_id, safe='~')}:{quote_plus(client_secret, safe='~')}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _scope_list(value: object) -> list[str] | None:
    if not isinstance(value, str) or not value:
        return None
    scopes = value.split(" ")
    if not scopes or len(scopes) > 64 or len(set(scopes)) != len(scopes):
        return None
    for scope in scopes:
        if not scope or len(scope) > 256:
            return None
        if any(ord(c) < 0x21 or ord(c) > 0x7E or c in {'"', "\\"} for c in scope):
            return None
    return scopes


def _audience_matches(value: object, resource: str) -> bool:
    if isinstance(value, str):
        return value == resource
    return isinstance(value, list) and bool(value) and len(value) <= 32 and all(isinstance(item, str) and item and len(item) <= 4096 for item in value) and len(set(value)) == len(value) and resource in value


class BridgeOAuthIntrospectionTokenVerifier(TokenVerifier):
    def __init__(self, credential: BridgeOAuthIntrospectionCredential, metadata: BridgeOAuthAuthorizationServerMetadata, resource_server_url: str, *, json_request: JsonRequest = request_oauth_json, clock: Callable[[], int] | None = None, timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS) -> None:
        if not isinstance(credential, BridgeOAuthIntrospectionCredential):
            raise TypeError("credential must be a BridgeOAuthIntrospectionCredential")
        if not isinstance(metadata, BridgeOAuthAuthorizationServerMetadata):
            raise TypeError("metadata must be BridgeOAuthAuthorizationServerMetadata")
        credential.validate()
        metadata.validate()
        require_https_endpoint(resource_server_url, "resource_server_url")
        if credential.issuer_url != metadata.issuer_url:
            raise BridgeOAuthIntrospectionVerifierError("OAuth introspection credential issuer differs from discovered authority")
        if not callable(json_request):
            raise TypeError("json_request must be callable")
        self.credential = credential
        self.metadata = metadata
        self.resource_server_url = resource_server_url
        self._json_request = json_request
        self._clock = clock or (lambda: int(time.time()))
        self._timeout_seconds = require_oauth_timeout(timeout_seconds)
        self._authorization_header = _basic_header(credential.client_id, credential.client_secret)

    async def verify_token(self, token: str) -> AccessToken | None:
        if not isinstance(token, str) or not token or token != token.strip() or len(token) > _MAX_BEARER_TOKEN_BYTES or len(token.encode("ascii", errors="ignore")) != len(token) or _BEARER_TOKEN_RE.fullmatch(token) is None:
            return None
        body = urlencode({"token": token, "token_type_hint": "access_token"}).encode("ascii")
        try:
            raw = await self._json_request(
                "POST",
                self.metadata.introspection_endpoint,
                {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": self._authorization_header,
                    "User-Agent": "HMS-GPT-VPS OAuth introspection",
                },
                body,
                self._timeout_seconds,
                MAX_OAUTH_JSON_BYTES,
            )
            return self._map_active(token, raw)
        except Exception:
            return None

    def _map_active(self, token: str, raw: Mapping[str, Any]) -> AccessToken | None:
        if raw.get("active") is not True:
            return None
        client_id, subject = raw.get("client_id"), raw.get("sub")
        if not isinstance(client_id, str) or not client_id or len(client_id) > 512 or not isinstance(subject, str) or not subject or len(subject) > 1024:
            return None
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in client_id + subject):
            return None
        scopes = _scope_list(raw.get("scope"))
        if scopes is None or MCP_CONTROL_SCOPE not in scopes or not _audience_matches(raw.get("aud"), self.resource_server_url):
            return None
        token_type = raw.get("token_type")
        if token_type is not None and (not isinstance(token_type, str) or token_type.casefold() != "bearer"):
            return None
        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, int) or now <= 0:
            return None
        exp = raw.get("exp")
        expires_at: int | None = None
        if exp is not None:
            if isinstance(exp, bool) or not isinstance(exp, int) or exp <= now:
                return None
            expires_at = exp
        nbf = raw.get("nbf")
        if nbf is not None and (isinstance(nbf, bool) or not isinstance(nbf, int) or nbf > now):
            return None
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scopes,
            expires_at=expires_at,
            resource=self.resource_server_url,
            subject=subject,
            claims={"iss": self.metadata.issuer_url, "aud": raw.get("aud")},
        )


def build_bridge_oauth_introspection_verifier_sync(credential: BridgeOAuthIntrospectionCredential, resource_server_url: str, *, discovery_request: SyncJsonRequest = request_oauth_json_sync, json_request: JsonRequest = request_oauth_json, timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS) -> BridgeOAuthIntrospectionTokenVerifier:
    credential.validate()
    metadata = discover_bridge_oauth_authorization_server_sync(
        credential.issuer_url,
        json_request=discovery_request,
        timeout_seconds=timeout_seconds,
    )
    return BridgeOAuthIntrospectionTokenVerifier(
        credential,
        metadata,
        resource_server_url,
        json_request=json_request,
        timeout_seconds=timeout_seconds,
    )


async def build_bridge_oauth_introspection_verifier(credential: BridgeOAuthIntrospectionCredential, resource_server_url: str, *, json_request: JsonRequest = request_oauth_json, timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS) -> BridgeOAuthIntrospectionTokenVerifier:
    credential.validate()
    metadata = await discover_bridge_oauth_authorization_server(
        credential.issuer_url,
        json_request=json_request,
        timeout_seconds=timeout_seconds,
    )
    return BridgeOAuthIntrospectionTokenVerifier(
        credential,
        metadata,
        resource_server_url,
        json_request=json_request,
        timeout_seconds=timeout_seconds,
    )
