from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Mapping
from urllib.parse import unquote

from .control_session_store import ControlSessionStoreError
from .pairing import PairingError
from .pairing_exchange import (
    PairingExchangeError,
    PairingExchangeIntegrityError,
    PairingExchangeRecoveryExpiredError,
    PairingExchangeRecoveryMismatchError,
    PairingExchangeStoreMismatchError,
    PairingSessionExchange,
)
from .pairing_readiness_runtime import PairingReadinessError, PairingReadinessRuntime
from .pairing_store import PairingNotFoundError, PairingStoreError


PAIRING_HTTP_SCHEMA_VERSION = 1
PAIRING_HTTP_MAX_BODY_BYTES = 4096
PAIRING_HTTP_MAX_PAIR_TOKEN_CHARS = 256
PAIRING_HTTP_MIN_CLIENT_NONCE_CHARS = 20
PAIRING_HTTP_MAX_CLIENT_NONCE_CHARS = 128
_PAIRING_ID_ALLOWED = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
_CLIENT_NONCE_ALLOWED = _PAIRING_ID_ALLOWED
_REQUEST_FIELDS = frozenset({"schema_version", "pair_token", "client_nonce"})


class PairingHttpServiceError(RuntimeError):
    pass


class PairingHttpRequestError(PairingHttpServiceError):
    pass


class PairingHttpUnsupportedMediaTypeError(PairingHttpRequestError):
    pass


class PairingHttpBodyTooLargeError(PairingHttpRequestError):
    pass


@dataclass(frozen=True)
class PairingHttpRequest:
    method: str
    path: str
    headers: Mapping[str, str] = field(repr=False)
    body: bytes = field(repr=False)


@dataclass(frozen=True)
class PairingHttpResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)

    def header(self, name: str) -> str | None:
        if not isinstance(name, str) or not name:
            raise ValueError("header name is required")
        wanted = name.casefold()
        for key, value in self.headers:
            if key.casefold() == wanted:
                return value
        return None


def _strict_json_object(data: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise PairingHttpRequestError("request JSON contains a duplicate key")
            result[key] = value
        return result

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PairingHttpRequestError("request body is not valid UTF-8") from exc
    try:
        payload = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise PairingHttpRequestError("request body is not valid strict JSON") from exc
    if not isinstance(payload, dict):
        raise PairingHttpRequestError("request body must be a JSON object")
    return payload


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(payload),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _fold_headers(headers: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        raise PairingHttpRequestError("headers must be a mapping")
    folded: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not key:
            raise PairingHttpRequestError("request header name is invalid")
        if not isinstance(value, str):
            raise PairingHttpRequestError("request header value is invalid")
        normalized = key.casefold()
        if normalized in folded:
            raise PairingHttpRequestError(
                "request contains duplicate case-insensitive headers"
            )
        folded[normalized] = value
    return folded


def _parse_pair_path(path: str) -> str | None:
    if not isinstance(path, str) or not path:
        return None
    if "?" in path or "#" in path:
        return None
    prefix = "/pair/"
    if not path.startswith(prefix):
        return None
    raw_pair_id = path[len(prefix) :]
    if not raw_pair_id or "/" in raw_pair_id:
        return None
    try:
        pair_id = unquote(raw_pair_id, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    # Canonical endpoint paths do not accept percent-encoded or alternate forms.
    if pair_id != raw_pair_id:
        return None
    if len(pair_id) > 128 or any(char not in _PAIRING_ID_ALLOWED for char in pair_id):
        return None
    return pair_id


def _parse_content_length(value: str) -> int:
    if not isinstance(value, str) or not value:
        raise PairingHttpRequestError("Content-Length is required")
    if not value.isascii() or not value.isdecimal():
        raise PairingHttpRequestError("Content-Length must be decimal ASCII")
    if len(value) > 1 and value.startswith("0"):
        raise PairingHttpRequestError("Content-Length is not canonical")
    length = int(value)
    if length > PAIRING_HTTP_MAX_BODY_BYTES:
        raise PairingHttpBodyTooLargeError("pairing request body exceeds size bound")
    return length


def _parse_request_payload(
    headers: Mapping[str, str],
    body: bytes,
) -> tuple[str, str]:
    folded = _fold_headers(headers)
    if "transfer-encoding" in folded:
        raise PairingHttpRequestError("Transfer-Encoding is not supported")

    content_encoding = folded.get("content-encoding")
    if content_encoding is not None and content_encoding.casefold() != "identity":
        raise PairingHttpUnsupportedMediaTypeError(
            "compressed pairing request bodies are not supported"
        )

    content_type = folded.get("content-type")
    if content_type is None or content_type.strip().casefold() not in {
        "application/json",
        "application/json; charset=utf-8",
    }:
        raise PairingHttpUnsupportedMediaTypeError(
            "pairing endpoint requires application/json"
        )

    declared_length = _parse_content_length(folded.get("content-length", ""))
    if not isinstance(body, bytes):
        raise PairingHttpRequestError("request body must be bytes")
    if len(body) > PAIRING_HTTP_MAX_BODY_BYTES:
        raise PairingHttpBodyTooLargeError("pairing request body exceeds size bound")
    if len(body) != declared_length:
        raise PairingHttpRequestError("Content-Length does not match request body")

    payload = _strict_json_object(body)
    if frozenset(payload) != _REQUEST_FIELDS:
        raise PairingHttpRequestError("pairing request fields do not match schema")
    schema = payload["schema_version"]
    if (
        isinstance(schema, bool)
        or not isinstance(schema, int)
        or schema != PAIRING_HTTP_SCHEMA_VERSION
    ):
        raise PairingHttpRequestError("pairing request schema_version is invalid")

    pair_token = payload["pair_token"]
    client_nonce = payload["client_nonce"]
    if (
        not isinstance(pair_token, str)
        or not pair_token
        or len(pair_token) > PAIRING_HTTP_MAX_PAIR_TOKEN_CHARS
    ):
        raise PairingHttpRequestError("pairing token is invalid")
    if (
        not isinstance(client_nonce, str)
        or not (
            PAIRING_HTTP_MIN_CLIENT_NONCE_CHARS
            <= len(client_nonce)
            <= PAIRING_HTTP_MAX_CLIENT_NONCE_CHARS
        )
        or any(char not in _CLIENT_NONCE_ALLOWED for char in client_nonce)
    ):
        raise PairingHttpRequestError("pairing client nonce is invalid")
    return pair_token, client_nonce


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise PairingHttpServiceError("session timestamp authority is invalid")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class PairingHttpService:
    """Strict HTTP boundary for one pairing->initial-session exchange.

    This class does not open a socket. The deployment/TLS layer must bound
    Content-Length before reading request bytes, then pass the exact method,
    path, headers and bounded body here. No request secret is included in repr,
    error bodies, or exception-derived HTTP responses.
    """

    def __init__(
        self,
        readiness: PairingReadinessRuntime,
        exchange: PairingSessionExchange,
    ) -> None:
        if not isinstance(readiness, PairingReadinessRuntime):
            raise TypeError("readiness must be a PairingReadinessRuntime")
        if not isinstance(exchange, PairingSessionExchange):
            raise TypeError("exchange must be a PairingSessionExchange")
        if readiness.pairing_store is not exchange.pairing_store:
            raise PairingHttpServiceError(
                "HTTP pairing service requires the exact pairing store used by readiness"
            )
        if readiness.config.instance_id.strip() != readiness.config.instance_id:
            raise PairingHttpServiceError("pairing runtime instance_id is not canonical")
        self.readiness = readiness
        self.exchange = exchange

    @staticmethod
    def _response(
        status: int,
        payload: Mapping[str, Any],
        *,
        allow: str | None = None,
    ) -> PairingHttpResponse:
        body = _json_bytes(payload)
        headers: list[tuple[str, str]] = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("Pragma", "no-cache"),
            ("Content-Length", str(len(body))),
        ]
        if allow is not None:
            headers.append(("Allow", allow))
        return PairingHttpResponse(
            status=status,
            headers=tuple(headers),
            body=body,
        )

    @classmethod
    def _error(
        cls,
        status: int,
        code: str,
        *,
        allow: str | None = None,
    ) -> PairingHttpResponse:
        return cls._response(
            status,
            {
                "schema_version": PAIRING_HTTP_SCHEMA_VERSION,
                "error": code,
            },
            allow=allow,
        )

    def handle(
        self,
        request: PairingHttpRequest,
    ) -> PairingHttpResponse:
        if not isinstance(request, PairingHttpRequest):
            raise TypeError("request must be a PairingHttpRequest")
        pair_id = _parse_pair_path(request.path)
        if pair_id is None:
            return self._error(404, "not_found")
        if request.method != "POST":
            return self._error(405, "method_not_allowed", allow="POST")

        try:
            pair_token, client_nonce = _parse_request_payload(
                request.headers,
                request.body,
            )
        except PairingHttpBodyTooLargeError:
            return self._error(413, "body_too_large")
        except PairingHttpUnsupportedMediaTypeError:
            return self._error(415, "unsupported_media_type")
        except PairingHttpRequestError:
            return self._error(400, "invalid_request")

        try:
            checked_at = self.readiness._now()
            before = self.readiness.observe()
        except Exception:
            return self._error(500, "internal_error")
        if before.pairing_ready is not True or before.pair_id != pair_id:
            return self._error(401, "pairing_rejected")

        try:
            grant = self.exchange.exchange(
                pair_id,
                pair_token,
                client_nonce,
                instance_id=self.readiness.config.instance_id,
                now=checked_at,
            )
        except (
            PairingNotFoundError,
            PairingError,
            PairingExchangeRecoveryExpiredError,
            PairingExchangeRecoveryMismatchError,
        ):
            return self._error(401, "pairing_rejected")
        except (
            PairingExchangeIntegrityError,
            PairingExchangeStoreMismatchError,
            PairingStoreError,
            ControlSessionStoreError,
            PairingReadinessError,
        ):
            return self._error(500, "internal_error")
        except PairingExchangeError:
            return self._error(400, "invalid_request")
        except Exception:
            return self._error(500, "internal_error")

        try:
            after = self.readiness.observe()
        except Exception:
            return self._error(500, "internal_error")
        if (
            after.pairing_ready is not True
            or after.paired is not True
            or after.pair_id != pair_id
        ):
            # The session may have been atomically committed, but no credential
            # leaves this boundary if fresh authenticated Agent presence cannot
            # still be proven after the exchange.
            return self._error(503, "pairing_unavailable")

        record = grant.record
        try:
            record.validate()
            document = {
                "schema_version": PAIRING_HTTP_SCHEMA_VERSION,
                "session_id": record.session_id,
                "instance_id": record.instance_id,
                "session_token": grant.token,
                "scopes": list(record.scopes),
                "issued_at": _iso(record.issued_at),
                "expires_at": _iso(record.expires_at),
                "epoch": record.epoch,
            }
        except Exception:
            return self._error(500, "internal_error")
        return self._response(200, document)
