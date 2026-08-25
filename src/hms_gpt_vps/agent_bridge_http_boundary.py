from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import Mapping

from .agent_bridge_service import AgentBridgeService, AgentBridgeServiceError
from .agent_command_store import AgentCommandStoreError
from .agent_connection_registry import AgentConnectionRegistryError
from .agent_transport_protocol import (
    ALLOWED_AGENT_ENDPOINTS,
    MAX_AGENT_BODY_BYTES,
    AgentAuthenticationError,
    AgentSignedRequest,
    AgentTransportError,
)


_JSON_CONTENT_TYPE = "application/json"
_REQUIRED_SIGNED_HEADERS = frozenset(
    {
        "x-hms-agent-schema",
        "x-hms-device-id",
        "x-hms-instance-id",
        "x-hms-boot-id",
        "x-hms-connection-epoch",
        "x-hms-timestamp",
        "x-hms-nonce",
        "x-hms-content-sha256",
        "authorization",
    }
)


class AgentBridgeHttpBoundaryError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentBridgeHttpRequest:
    method: str
    path: str
    headers: tuple[tuple[str, str], ...] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class AgentBridgeHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


def _canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    try:
        data = json.dumps(
            dict(payload),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentBridgeHttpBoundaryError(
            "Bridge HTTP response is not JSON-safe"
        ) from exc
    if not data or len(data) > MAX_AGENT_BODY_BYTES:
        raise AgentBridgeHttpBoundaryError(
            "Bridge HTTP response exceeds transport bound"
        )
    return data


def _response(status_code: int, payload: Mapping[str, object]) -> AgentBridgeHttpResponse:
    body = _canonical_json_bytes(payload)
    return AgentBridgeHttpResponse(
        status_code=status_code,
        headers={
            "Content-Type": _JSON_CONTENT_TYPE,
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store",
        },
        body=body,
    )


def _error(status_code: int, code: str) -> AgentBridgeHttpResponse:
    return _response(status_code, {"error": code})


def _fold_headers(headers: object) -> dict[str, str]:
    if not isinstance(headers, tuple):
        raise AgentBridgeHttpBoundaryError(
            "request headers must preserve raw header occurrences"
        )
    folded: dict[str, str] = {}
    for item in headers:
        if not isinstance(item, tuple) or len(item) != 2:
            raise AgentBridgeHttpBoundaryError(
                "request header occurrence is invalid"
            )
        key, value = item
        if not isinstance(key, str) or not key:
            raise AgentBridgeHttpBoundaryError("request header name is invalid")
        if not isinstance(value, str):
            raise AgentBridgeHttpBoundaryError("request header value must be text")
        if "\r" in key or "\n" in key or "\r" in value or "\n" in value:
            raise AgentBridgeHttpBoundaryError(
                "request headers contain invalid characters"
            )
        normalized = key.casefold()
        if normalized in folded:
            raise AgentBridgeHttpBoundaryError(
                "request contains duplicate case-insensitive headers"
            )
        folded[normalized] = value
    return folded


def _validate_content_type(value: str | None) -> None:
    if value is None:
        raise AgentBridgeHttpBoundaryError("Content-Type is required")
    parts = [part.strip().casefold() for part in value.split(";")]
    if not parts or parts[0] != _JSON_CONTENT_TYPE:
        raise AgentBridgeHttpBoundaryError(
            "Content-Type must be application/json"
        )
    parameters = parts[1:]
    if parameters not in ([], ["charset=utf-8"]):
        raise AgentBridgeHttpBoundaryError(
            "Content-Type parameters are unsupported"
        )


def _validate_request_shape(request: AgentBridgeHttpRequest) -> dict[str, str]:
    if not isinstance(request, AgentBridgeHttpRequest):
        raise TypeError("request must be an AgentBridgeHttpRequest")
    if request.method != "POST":
        raise AgentBridgeHttpBoundaryError("Agent Bridge HTTP supports POST only")
    if request.path not in ALLOWED_AGENT_ENDPOINTS:
        raise AgentBridgeHttpBoundaryError("unsupported Agent Bridge endpoint")
    if not isinstance(request.body, bytes):
        raise AgentBridgeHttpBoundaryError("request body must be bytes")
    if not request.body:
        raise AgentBridgeHttpBoundaryError("request body must not be empty")
    if len(request.body) > MAX_AGENT_BODY_BYTES:
        raise OverflowError("request body exceeds Agent transport bound")

    headers = _fold_headers(request.headers)
    if "transfer-encoding" in headers:
        raise AgentBridgeHttpBoundaryError(
            "Transfer-Encoding is not supported"
        )
    content_length = headers.get("content-length")
    if content_length is None or content_length != str(len(request.body)):
        raise AgentBridgeHttpBoundaryError(
            "Content-Length does not match exact request body"
        )
    _validate_content_type(headers.get("content-type"))
    missing = _REQUIRED_SIGNED_HEADERS.difference(headers)
    if missing:
        raise AgentAuthenticationError(
            "Agent request is missing signed authentication headers"
        )
    return headers


class AgentBridgeHttpBoundary:
    """Strict HTTP boundary for the four authenticated outbound-Agent routes.

    This class does not open a socket. A later TLS listener/deployment layer may
    translate its native HTTP request into ``AgentBridgeHttpRequest``. Raw HTTP
    header occurrences must be preserved so duplicate names cannot be hidden by
    dict normalization. Only the nine signed HMS headers are forwarded to the
    service; proxy, cookie and forwarding metadata never become HMAC authority.
    """

    def __init__(self, service: AgentBridgeService) -> None:
        if not isinstance(service, AgentBridgeService):
            raise TypeError("service must be an AgentBridgeService")
        self.service = service

    def handle(
        self,
        request: AgentBridgeHttpRequest,
        *,
        now: datetime | None = None,
    ) -> AgentBridgeHttpResponse:
        try:
            headers = _validate_request_shape(request)
            signed_headers = {
                key: headers[key]
                for key in _REQUIRED_SIGNED_HEADERS
            }
            payload = self.service.handle(
                AgentSignedRequest(
                    method=request.method,
                    path=request.path,
                    body=request.body,
                    headers=signed_headers,
                ),
                now=now,
            )
            return _response(200, payload)
        except OverflowError:
            return _error(413, "request_too_large")
        except AgentAuthenticationError:
            return _error(401, "authentication_failed")
        except AgentTransportError:
            return _error(400, "invalid_agent_request")
        except AgentBridgeHttpBoundaryError:
            return _error(400, "invalid_http_request")
        except (AgentConnectionRegistryError, AgentCommandStoreError):
            return _error(409, "agent_state_conflict")
        except AgentBridgeServiceError:
            return _error(503, "bridge_unavailable")
        except Exception:
            return _error(503, "bridge_unavailable")
