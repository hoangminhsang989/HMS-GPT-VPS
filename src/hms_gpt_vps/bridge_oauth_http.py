from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import ssl
from typing import Any, Awaitable, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


MAX_OAUTH_JSON_BYTES = 64 * 1024
DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS = 10
SyncJsonRequest = Callable[[str, str, Mapping[str, str], bytes | None, int, int], dict[str, Any]]
JsonRequest = Callable[[str, str, Mapping[str, str], bytes | None, int, int], Awaitable[dict[str, Any]]]


class BridgeOAuthHttpError(RuntimeError):
    pass


class BridgeOAuthDiscoveryError(BridgeOAuthHttpError):
    pass


def require_oauth_timeout(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 60:
        raise BridgeOAuthHttpError("OAuth HTTP timeout is invalid")
    return value


def require_https_issuer(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 2048:
        raise BridgeOAuthDiscoveryError("OAuth issuer URL is invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise BridgeOAuthDiscoveryError("OAuth issuer URL must be canonical HTTPS")
    return value


def require_https_endpoint(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > 4096:
        raise BridgeOAuthDiscoveryError(f"{name} is invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise BridgeOAuthDiscoveryError(f"{name} must be HTTPS without userinfo or fragment")
    return value


def authorization_server_metadata_url(issuer_url: str) -> str:
    issuer = require_https_issuer(issuer_url)
    parsed = urlsplit(issuer)
    issuer_path = parsed.path.rstrip("/")
    suffix = "/.well-known/oauth-authorization-server"
    path = suffix + issuer_path if issuer_path else suffix
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in items:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def request_oauth_json_sync(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout_seconds: int, max_bytes: int) -> dict[str, Any]:
    if method not in {"GET", "POST"}:
        raise BridgeOAuthHttpError("unsupported OAuth HTTP method")
    require_oauth_timeout(timeout_seconds)
    require_https_endpoint(url, "OAuth endpoint")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or not 1 <= max_bytes <= 1024 * 1024:
        raise BridgeOAuthHttpError("OAuth HTTP response bound is invalid")
    request = Request(url, data=body, headers=dict(headers), method=method)
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())
    try:
        with opener.open(request, timeout=float(timeout_seconds)) as response:
            if int(getattr(response, "status", 0)) != 200:
                raise BridgeOAuthHttpError("OAuth endpoint returned non-200 status")
            if response.headers.get_content_type() != "application/json":
                raise BridgeOAuthHttpError("OAuth endpoint did not return application/json")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise BridgeOAuthHttpError("OAuth endpoint Content-Length is invalid") from exc
                if declared < 0 or declared > max_bytes:
                    raise BridgeOAuthHttpError("OAuth endpoint response exceeds safety bound")
            data = response.read(max_bytes + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise BridgeOAuthHttpError("OAuth HTTPS request failed") from exc
    if not data or len(data) > max_bytes:
        raise BridgeOAuthHttpError("OAuth endpoint response size is invalid")
    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise BridgeOAuthHttpError("OAuth endpoint JSON is invalid") from exc
    if not isinstance(raw, dict):
        raise BridgeOAuthHttpError("OAuth endpoint JSON must be an object")
    return raw


async def request_oauth_json(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout_seconds: int, max_bytes: int) -> dict[str, Any]:
    return await asyncio.to_thread(request_oauth_json_sync, method, url, headers, body, timeout_seconds, max_bytes)


@dataclass(frozen=True)
class BridgeOAuthAuthorizationServerMetadata:
    issuer_url: str
    introspection_endpoint: str

    def validate(self) -> None:
        require_https_issuer(self.issuer_url)
        require_https_endpoint(self.introspection_endpoint, "introspection_endpoint")


def _metadata_from_mapping(issuer: str, raw: Mapping[str, Any]) -> BridgeOAuthAuthorizationServerMetadata:
    if raw.get("issuer") != issuer:
        raise BridgeOAuthDiscoveryError("authorization-server metadata issuer differs from configured authority")
    endpoint = require_https_endpoint(raw.get("introspection_endpoint"), "introspection_endpoint")
    methods = raw.get("introspection_endpoint_auth_methods_supported")
    if not isinstance(methods, list) or not methods or len(methods) > 32 or any(not isinstance(item, str) or not item or len(item) > 128 for item in methods) or len(set(methods)) != len(methods) or "client_secret_basic" not in methods:
        raise BridgeOAuthDiscoveryError("authorization server does not explicitly advertise client_secret_basic introspection")
    metadata = BridgeOAuthAuthorizationServerMetadata(issuer, endpoint)
    metadata.validate()
    return metadata


def discover_bridge_oauth_authorization_server_sync(issuer_url: str, *, json_request: SyncJsonRequest = request_oauth_json_sync, timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS) -> BridgeOAuthAuthorizationServerMetadata:
    issuer = require_https_issuer(issuer_url)
    require_oauth_timeout(timeout_seconds)
    raw = json_request("GET", authorization_server_metadata_url(issuer), {"Accept": "application/json", "User-Agent": "HMS-GPT-VPS OAuth discovery"}, None, timeout_seconds, MAX_OAUTH_JSON_BYTES)
    return _metadata_from_mapping(issuer, raw)


async def discover_bridge_oauth_authorization_server(issuer_url: str, *, json_request: JsonRequest = request_oauth_json, timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS) -> BridgeOAuthAuthorizationServerMetadata:
    issuer = require_https_issuer(issuer_url)
    require_oauth_timeout(timeout_seconds)
    raw = await json_request("GET", authorization_server_metadata_url(issuer), {"Accept": "application/json", "User-Agent": "HMS-GPT-VPS OAuth discovery"}, None, timeout_seconds, MAX_OAUTH_JSON_BYTES)
    return _metadata_from_mapping(issuer, raw)
