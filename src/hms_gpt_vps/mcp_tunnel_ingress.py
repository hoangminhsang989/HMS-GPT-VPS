from __future__ import annotations

from collections.abc import Mapping
import re
import secrets
from typing import Any, Awaitable, Callable

MCP_TUNNEL_INGRESS_HEADER = "X-HMS-Tunnel-Ingress"
MCP_TUNNEL_INGRESS_TOKEN_ENV = "HMS_TUNNEL_INGRESS_TOKEN"
MCP_EXTRA_HEADERS_ENV = "MCP_EXTRA_HEADERS"
MCP_TUNNEL_INGRESS_PATH = "/mcp"
MCP_TUNNEL_INGRESS_TOKEN_HEX_LENGTH = 64
MCP_TUNNEL_EXTRA_HEADER_SPEC = (
    f"{MCP_TUNNEL_INGRESS_HEADER}: env:{MCP_TUNNEL_INGRESS_TOKEN_ENV}"
)

_TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
_HEADER_BYTES = MCP_TUNNEL_INGRESS_HEADER.lower().encode("ascii")


class McpTunnelIngressError(RuntimeError):
    pass


AsgiReceive = Callable[[], Awaitable[dict[str, Any]]]
AsgiSend = Callable[[dict[str, Any]], Awaitable[None]]
AsgiApp = Callable[[dict[str, Any], AsgiReceive, AsgiSend], Awaitable[None]]


def require_mcp_tunnel_ingress_token(token: str) -> str:
    if not isinstance(token, str) or _TOKEN_RE.fullmatch(token) is None:
        raise McpTunnelIngressError(
            "MCP tunnel ingress token must be 64 lowercase hexadecimal characters"
        )
    return token


def generate_mcp_tunnel_ingress_token() -> str:
    token = secrets.token_hex(32)
    return require_mcp_tunnel_ingress_token(token)


def build_mcp_tunnel_ingress_child_environment(
    base_environment: Mapping[str, str],
    *,
    token: str,
) -> dict[str, str]:
    if not isinstance(base_environment, Mapping):
        raise TypeError("base_environment must be a mapping")
    checked = require_mcp_tunnel_ingress_token(token)
    child: dict[str, str] = {}
    for key, value in base_environment.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("base_environment keys and values must be strings")
        if "\x00" in key or "\x00" in value:
            raise McpTunnelIngressError("base_environment contains a NUL character")
        if key.casefold() in {
            MCP_TUNNEL_INGRESS_TOKEN_ENV.casefold(),
            MCP_EXTRA_HEADERS_ENV.casefold(),
        }:
            raise McpTunnelIngressError(
                "base_environment already contains MCP tunnel ingress authority"
            )
        child[key] = value
    child[MCP_TUNNEL_INGRESS_TOKEN_ENV] = checked
    child[MCP_EXTRA_HEADERS_ENV] = MCP_TUNNEL_EXTRA_HEADER_SPEC
    return child


class McpTunnelIngressGate:
    """ASGI gate requiring the per-start tunnel capability on exact /mcp only."""

    def __init__(self, app: AsgiApp, *, token: str) -> None:
        if not callable(app):
            raise TypeError("app must be callable")
        self._app = app
        self._expected_token = require_mcp_tunnel_ingress_token(token)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(path={MCP_TUNNEL_INGRESS_PATH!r})"

    @staticmethod
    async def _reject(send: AsgiSend) -> None:
        body = b"not found"
        await send(
            {
                "type": "http.response.start",
                "status": 404,
                "headers": [
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: AsgiReceive,
        send: AsgiSend,
    ) -> None:
        if not isinstance(scope, dict):
            raise TypeError("scope must be a dict")
        if scope.get("type") != "http" or scope.get("path") != MCP_TUNNEL_INGRESS_PATH:
            await self._app(scope, receive, send)
            return

        raw_headers = scope.get("headers", [])
        if not isinstance(raw_headers, list):
            await self._reject(send)
            return
        values: list[bytes] = []
        for entry in raw_headers:
            if (
                not isinstance(entry, tuple)
                or len(entry) != 2
                or not isinstance(entry[0], bytes)
                or not isinstance(entry[1], bytes)
            ):
                await self._reject(send)
                return
            if entry[0].lower() == _HEADER_BYTES:
                values.append(entry[1])
        if len(values) != 1:
            await self._reject(send)
            return
        try:
            candidate = values[0].decode("ascii", errors="strict")
        except UnicodeDecodeError:
            await self._reject(send)
            return
        if _TOKEN_RE.fullmatch(candidate) is None or not secrets.compare_digest(
            candidate,
            self._expected_token,
        ):
            await self._reject(send)
            return
        await self._app(scope, receive, send)
