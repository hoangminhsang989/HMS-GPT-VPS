from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import ssl
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    OpenerDirector,
    ProxyHandler,
    Request,
    build_opener,
)

from .agent_transport_protocol import (
    ALLOWED_AGENT_ENDPOINTS,
    MAX_AGENT_BODY_BYTES,
    AgentDeviceCredential,
    AgentTransportError,
    _canonical_json,
    sign_agent_request,
)


MAX_AGENT_RESPONSE_BYTES = MAX_AGENT_BODY_BYTES
DEFAULT_AGENT_HTTP_TIMEOUT_SECONDS = 30


class AgentHttpsClientError(RuntimeError):
    pass


class AgentHttpsNetworkError(AgentHttpsClientError):
    pass


class AgentHttpsResponseError(AgentHttpsClientError):
    pass


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class AgentHttpsClientConfig:
    bridge_origin: str
    timeout_seconds: int = DEFAULT_AGENT_HTTP_TIMEOUT_SECONDS
    max_response_bytes: int = MAX_AGENT_RESPONSE_BYTES
    allow_environment_proxy: bool = False
    user_agent: str = "HMS-GPT-VPS-Agent/1"

    def validate(self) -> None:
        if not isinstance(self.bridge_origin, str) or not self.bridge_origin.strip():
            raise ValueError("bridge_origin is required")
        parsed = urlsplit(self.bridge_origin)
        if parsed.scheme.lower() != "https":
            raise ValueError("bridge_origin must use https")
        if not parsed.hostname:
            raise ValueError("bridge_origin must include a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("bridge_origin must not contain URL credentials")
        if parsed.query:
            raise ValueError("bridge_origin must not contain a query")
        if parsed.fragment:
            raise ValueError("bridge_origin must not contain a fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("bridge_origin must be an origin without a path prefix")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("bridge_origin contains an invalid port") from exc
        if not isinstance(self.timeout_seconds, int) or isinstance(self.timeout_seconds, bool):
            raise ValueError("timeout_seconds must be an integer")
        if not 1 <= self.timeout_seconds <= 300:
            raise ValueError("timeout_seconds must be between 1 and 300")
        if not isinstance(self.max_response_bytes, int) or isinstance(self.max_response_bytes, bool):
            raise ValueError("max_response_bytes must be an integer")
        if not 1 <= self.max_response_bytes <= MAX_AGENT_RESPONSE_BYTES:
            raise ValueError("max_response_bytes is outside allowed bounds")
        if not isinstance(self.user_agent, str) or not self.user_agent.strip():
            raise ValueError("user_agent is required")
        if "\r" in self.user_agent or "\n" in self.user_agent:
            raise ValueError("user_agent contains invalid characters")

    @property
    def normalized_origin(self) -> str:
        self.validate()
        parsed = urlsplit(self.bridge_origin)
        host = parsed.hostname
        assert host is not None
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = parsed.port
        default_port = 443
        authority = host if port in {None, default_port} else f"{host}:{port}"
        return f"https://{authority}"


class AgentHttpsClient:
    """Fail-closed outbound HTTPS transport for the HMS Agent.

    Authentication is delegated to `sign_agent_request`; this class only owns
    HTTPS URL construction, redirect/proxy behavior, bounded response parsing
    and endpoint-specific convenience calls. It never opens a listening socket.
    """

    def __init__(
        self,
        config: AgentHttpsClientConfig,
        credential: AgentDeviceCredential,
        *,
        boot_id: str,
        connection_epoch: int,
        ssl_context: ssl.SSLContext | None = None,
        opener: OpenerDirector | Any | None = None,
    ) -> None:
        config.validate()
        credential.validate()
        if not isinstance(boot_id, str) or not boot_id:
            raise ValueError("boot_id is required")
        if not isinstance(connection_epoch, int) or isinstance(connection_epoch, bool) or connection_epoch < 1:
            raise ValueError("connection_epoch must be a positive integer")
        self.config = config
        self.credential = credential
        self.boot_id = boot_id
        self.connection_epoch = connection_epoch
        self._opener = opener or self._build_default_opener(ssl_context)

    def _build_default_opener(self, ssl_context: ssl.SSLContext | None) -> OpenerDirector:
        context = ssl_context or ssl.create_default_context()
        if context.check_hostname is not True or context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError("TLS context must require certificate and hostname verification")
        handlers: list[Any] = [_NoRedirectHandler(), HTTPSHandler(context=context)]
        if not self.config.allow_environment_proxy:
            handlers.insert(0, ProxyHandler({}))
        return build_opener(*handlers)

    def _url_for(self, path: str) -> str:
        if path not in ALLOWED_AGENT_ENDPOINTS:
            raise AgentTransportError(f"unsupported Agent transport endpoint: {path}")
        return self.config.normalized_origin + path

    @staticmethod
    def _strict_json_object(data: bytes) -> dict[str, Any]:
        def object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate JSON key: {key}")
                result[key] = value
            return result

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AgentHttpsResponseError("Bridge response is not valid UTF-8") from exc
        try:
            value = json.loads(text, object_pairs_hook=object_pairs_no_duplicates)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AgentHttpsResponseError("Bridge response is not valid strict JSON") from exc
        if not isinstance(value, dict):
            raise AgentHttpsResponseError("Bridge response must be a JSON object")
        return value

    def post_json(
        self,
        path: str,
        payload: Mapping[str, Any],
        *,
        now: datetime | None = None,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        body = _canonical_json(payload)
        signed = sign_agent_request(
            self.credential,
            path=path,
            body=body,
            boot_id=self.boot_id,
            connection_epoch=self.connection_epoch,
            now=now,
            nonce=nonce,
        )
        headers = dict(signed.headers)
        headers.update(
            {
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "application/json",
                "User-Agent": self.config.user_agent,
                "Cache-Control": "no-store",
            }
        )
        request = Request(
            self._url_for(path),
            data=signed.body,
            headers=headers,
            method="POST",
        )

        try:
            response = self._opener.open(request, timeout=self.config.timeout_seconds)
        except HTTPError as exc:
            raise AgentHttpsResponseError(f"Bridge returned HTTP status {exc.code}") from None
        except (URLError, TimeoutError, OSError) as exc:
            raise AgentHttpsNetworkError("Bridge HTTPS request failed") from None

        try:
            status = getattr(response, "status", None)
            if status is None and hasattr(response, "getcode"):
                status = response.getcode()
            if status != 200:
                raise AgentHttpsResponseError(f"Bridge returned HTTP status {status}")

            content_type = ""
            response_headers = getattr(response, "headers", None)
            if response_headers is not None:
                if hasattr(response_headers, "get_content_type"):
                    content_type = str(response_headers.get_content_type()).lower()
                elif hasattr(response_headers, "get"):
                    raw = response_headers.get("Content-Type", "")
                    content_type = str(raw).split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise AgentHttpsResponseError("Bridge response Content-Type must be application/json")

            data = response.read(self.config.max_response_bytes + 1)
            if len(data) > self.config.max_response_bytes:
                raise AgentHttpsResponseError("Bridge response exceeds maximum size")
            return self._strict_json_object(data)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    def hello(self, payload: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
        return self.post_json("/agent/v1/hello", payload, **kwargs)

    def heartbeat(self, payload: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
        return self.post_json("/agent/v1/heartbeat", payload, **kwargs)

    def poll(self, payload: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
        return self.post_json("/agent/v1/poll", payload, **kwargs)

    def submit_result(self, payload: Mapping[str, Any], **kwargs: Any) -> dict[str, Any]:
        return self.post_json("/agent/v1/result", payload, **kwargs)
