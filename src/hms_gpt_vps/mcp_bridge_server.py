from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

from pydantic import AnyHttpUrl
from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.types import ToolAnnotations

from .principal_agent_control_service import (
    PrincipalAgentControlAmbiguousError,
    PrincipalAgentControlApprovalRequiredError,
    PrincipalAgentControlConflictError,
    PrincipalAgentControlError,
    PrincipalAgentControlUnavailableError,
    PrincipalControlStatus,
)
from .principal_pairing_service import (
    PrincipalPairingConflictError,
    PrincipalPairingError,
    PrincipalPairingRejectedError,
    PrincipalPairingResult,
    PrincipalPairingUnavailableError,
    TrustedIntegrationPrincipal,
)

MCP_CONTROL_SCOPE = "hms.vps.control"
MCP_PRINCIPAL_NAMESPACE = "mcp-oauth-principal-v1"
_PRINCIPAL_DOMAIN = b"hms-gpt-vps/mcp-oauth-principal/v1\x00"
_LOOPBACK_HOST = "127.0.0.1"
_MCP_PATH = "/mcp"


class HmsMcpBridgeError(RuntimeError):
    pass


class HmsMcpAuthenticationError(HmsMcpBridgeError):
    pass


class HmsMcpToolError(HmsMcpBridgeError):
    pass


class PrincipalControlFacade(Protocol):
    def pair_vps(self, principal: TrustedIntegrationPrincipal, pairing_link: str) -> PrincipalPairingResult: ...
    def read_file(self, principal: TrustedIntegrationPrincipal, *, instance_id: str, request_id: str, path: str) -> PrincipalControlStatus: ...
    def write_file(self, principal: TrustedIntegrationPrincipal, *, instance_id: str, request_id: str, path: str, content: str) -> PrincipalControlStatus: ...


def _require_https_url(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise HmsMcpBridgeError(f"{name} must be a non-empty HTTPS URL")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise HmsMcpBridgeError(f"{name} must be a canonical HTTPS URL")
    return value


def _require_client_id(value: object, name: str = "expected_client_id") -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise HmsMcpBridgeError(f"{name} is invalid")
    return value


@dataclass(frozen=True)
class HmsMcpBridgeConfig:
    issuer_url: str
    resource_server_url: str
    port: int = 8765
    expected_client_id: str | None = None

    def validate(self) -> None:
        _require_https_url(self.issuer_url, "issuer_url")
        _require_https_url(self.resource_server_url, "resource_server_url")
        if self.expected_client_id is not None:
            _require_client_id(self.expected_client_id)
        if (
            isinstance(self.port, bool)
            or not isinstance(self.port, int)
            or not 1024 <= self.port <= 65535
        ):
            raise HmsMcpBridgeError("port must be an integer from 1024 through 65535")


def _issuer(token: AccessToken) -> str | None:
    if not isinstance(token.claims, dict):
        return None
    value = token.claims.get("iss")
    return value if isinstance(value, str) else None


def _validate_access_token(
    token: object,
    config: HmsMcpBridgeConfig,
    *,
    now_epoch: int | None = None,
) -> AccessToken:
    config.validate()
    if not isinstance(token, AccessToken):
        raise HmsMcpAuthenticationError("verified bearer authority is invalid")
    try:
        client_id = _require_client_id(token.client_id, "authenticated client identity")
    except HmsMcpBridgeError as exc:
        raise HmsMcpAuthenticationError("authenticated client identity is unavailable") from exc
    if (
        config.expected_client_id is not None
        and client_id != config.expected_client_id
    ):
        raise HmsMcpAuthenticationError(
            "authenticated client identity differs from configured authority"
        )
    if not isinstance(token.subject, str) or not token.subject or len(token.subject) > 1024:
        raise HmsMcpAuthenticationError("authenticated user subject is unavailable")
    if token.resource != config.resource_server_url:
        raise HmsMcpAuthenticationError("bearer token targets another resource")
    if _issuer(token) != config.issuer_url:
        raise HmsMcpAuthenticationError("bearer issuer differs from configured authority")
    if (
        not isinstance(token.scopes, list)
        or any(not isinstance(scope, str) or not scope for scope in token.scopes)
        or len(set(token.scopes)) != len(token.scopes)
        or MCP_CONTROL_SCOPE not in token.scopes
    ):
        raise HmsMcpAuthenticationError("bearer token lacks canonical HMS control scope")
    if token.expires_at is not None:
        if isinstance(token.expires_at, bool) or not isinstance(token.expires_at, int) or token.expires_at <= 0:
            raise HmsMcpAuthenticationError("bearer expiry is malformed")
        if now_epoch is not None and token.expires_at <= now_epoch:
            raise HmsMcpAuthenticationError("bearer token is expired")
    return token


class ResourceBoundTokenVerifier(TokenVerifier):
    def __init__(
        self,
        upstream: TokenVerifier,
        config: HmsMcpBridgeConfig,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not callable(getattr(upstream, "verify_token", None)):
            raise TypeError("upstream must implement TokenVerifier.verify_token")
        config.validate()
        self.upstream = upstream
        self.config = config
        self._clock = clock or (lambda: int(time.time()))

    async def verify_token(self, token: str) -> AccessToken | None:
        if not isinstance(token, str) or not token:
            return None
        try:
            candidate = await self.upstream.verify_token(token)
        except Exception:
            return None
        if candidate is None:
            return None
        try:
            return _validate_access_token(candidate, self.config, now_epoch=self._clock())
        except HmsMcpAuthenticationError:
            return None


def principal_from_access_token(
    token: AccessToken,
    config: HmsMcpBridgeConfig,
) -> TrustedIntegrationPrincipal:
    checked = _validate_access_token(token, config, now_epoch=int(time.time()))
    identity = json.dumps(
        {
            "issuer": config.issuer_url,
            "client_id": checked.client_id,
            "subject": checked.subject,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    principal = TrustedIntegrationPrincipal(
        namespace=MCP_PRINCIPAL_NAMESPACE,
        subject=hashlib.sha256(_PRINCIPAL_DOMAIN + identity).hexdigest(),
    )
    principal.validate()
    return principal


def current_authenticated_principal(config: HmsMcpBridgeConfig) -> TrustedIntegrationPrincipal:
    token = get_access_token()
    if token is None:
        raise HmsMcpAuthenticationError("authenticated MCP principal is unavailable")
    return principal_from_access_token(token, config)


class HmsMcpToolAdapter:
    def __init__(self, control: PrincipalControlFacade, config: HmsMcpBridgeConfig) -> None:
        for name in ("pair_vps", "read_file", "write_file"):
            if not callable(getattr(control, name, None)):
                raise TypeError("control must implement pair_vps/read_file/write_file")
        config.validate()
        self.control = control
        self.config = config

    def _principal(self) -> TrustedIntegrationPrincipal:
        return current_authenticated_principal(self.config)

    def pair_vps(self, pairing_link: str) -> dict[str, Any]:
        try:
            result = self.control.pair_vps(self._principal(), pairing_link)
        except PrincipalPairingRejectedError:
            raise HmsMcpToolError("pairing_rejected") from None
        except PrincipalPairingUnavailableError:
            raise HmsMcpToolError("pairing_unavailable") from None
        except PrincipalPairingConflictError:
            raise HmsMcpToolError("pairing_conflict") from None
        except PrincipalPairingError:
            raise HmsMcpToolError("pairing_failed") from None
        return {
            "instance_id": result.instance_id,
            "session_id": result.session_id,
            "scopes": list(result.scopes),
            "expires_at": result.expires_at.isoformat().replace("+00:00", "Z"),
        }

    def read_file(self, instance_id: str, request_id: str, path: str) -> dict[str, Any]:
        return self._control_call(
            lambda: self.control.read_file(
                self._principal(),
                instance_id=instance_id,
                request_id=request_id,
                path=path,
            )
        )

    def write_file(self, instance_id: str, request_id: str, path: str, content: str) -> dict[str, Any]:
        return self._control_call(
            lambda: self.control.write_file(
                self._principal(),
                instance_id=instance_id,
                request_id=request_id,
                path=path,
                content=content,
            )
        )

    @staticmethod
    def _control_call(call: Callable[[], PrincipalControlStatus]) -> dict[str, Any]:
        try:
            return call().to_dict()
        except PrincipalAgentControlApprovalRequiredError:
            raise HmsMcpToolError("approval_required") from None
        except PrincipalAgentControlUnavailableError:
            raise HmsMcpToolError("agent_unavailable") from None
        except PrincipalAgentControlAmbiguousError:
            raise HmsMcpToolError("command_ambiguous") from None
        except PrincipalAgentControlConflictError:
            raise HmsMcpToolError("control_conflict") from None
        except PrincipalAgentControlError:
            raise HmsMcpToolError("control_failed") from None


def build_hms_mcp_server(
    control: PrincipalControlFacade,
    upstream_token_verifier: TokenVerifier,
    config: HmsMcpBridgeConfig,
) -> MCPServer:
    config.validate()
    adapter = HmsMcpToolAdapter(control, config)
    server = MCPServer(
        "HMS-GPT-VPS",
        token_verifier=ResourceBoundTokenVerifier(upstream_token_verifier, config),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(config.issuer_url),
            resource_server_url=AnyHttpUrl(config.resource_server_url),
            required_scopes=[MCP_CONTROL_SCOPE],
        ),
        log_level="WARNING",
    )

    @server.tool(
        title="Pair HMS VPS",
        description="Bind the local one-time HMS VPS link to the authenticated integration principal.",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def pair_vps(pairing_link: str) -> dict[str, Any]:
        return adapter.pair_vps(pairing_link)

    @server.tool(
        title="Read file from HMS VPS",
        description="Read one workspace file through the Bridge and outbound managed guest Agent.",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def read_file(instance_id: str, request_id: str, path: str) -> dict[str, Any]:
        return adapter.read_file(instance_id, request_id, path)

    @server.tool(
        title="Create file in HMS VPS",
        description="Create one new UTF-8 workspace file. Existing files are never overwritten.",
        annotations=ToolAnnotations(
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def write_file(instance_id: str, request_id: str, path: str, content: str) -> dict[str, Any]:
        return adapter.write_file(instance_id, request_id, path, content)

    return server


def run_loopback_mcp_server(server: MCPServer, config: HmsMcpBridgeConfig) -> None:
    config.validate()
    server.run(
        transport="streamable-http",
        host=_LOOPBACK_HOST,
        port=config.port,
        streamable_http_path=_MCP_PATH,
        stateless_http=True,
        json_response=True,
    )
