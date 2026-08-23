from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
from typing import Any, Mapping

from .agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES


AGENT_TRANSPORT_SCHEMA_VERSION = 1
AGENT_DEVICE_SECRET_BYTES = 32
AGENT_REQUEST_NONCE_BYTES = 16
MAX_AGENT_BODY_BYTES = 2 * 1024 * 1024
MAX_AGENT_CLOCK_SKEW_SECONDS = 90
ALLOWED_AGENT_ENDPOINTS = frozenset(
    {
        "/agent/v1/hello",
        "/agent/v1/heartbeat",
        "/agent/v1/poll",
        "/agent/v1/result",
    }
)
_AUTH_SCHEME = "HMS-Agent-HMAC-SHA256"
_AGENT_REQUEST_DOMAIN = "hms-gpt-vps/agent-request/v1"
_BRIDGE_COMMAND_DOMAIN = "hms-gpt-vps/bridge-command/v1"
_SAFE_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


class AgentTransportError(ValueError):
    pass


class AgentAuthenticationError(PermissionError):
    pass


class AgentClockSkewError(AgentAuthenticationError):
    pass


class AgentBodyIntegrityError(AgentAuthenticationError):
    pass


@dataclass(frozen=True)
class AgentDeviceCredential:
    instance_id: str
    device_id: str
    secret: bytes = field(repr=False)

    def validate(self) -> None:
        _validate_identifier(self.instance_id, "instance_id")
        _validate_identifier(self.device_id, "device_id")
        if not isinstance(self.secret, bytes):
            raise AgentTransportError("device secret must be bytes")
        if len(self.secret) != AGENT_DEVICE_SECRET_BYTES:
            raise AgentTransportError("device secret must contain exactly 32 bytes")

    @classmethod
    def generate(cls, instance_id: str) -> "AgentDeviceCredential":
        _validate_identifier(instance_id, "instance_id")
        credential = cls(
            instance_id=instance_id,
            device_id=secrets.token_urlsafe(16),
            secret=secrets.token_bytes(AGENT_DEVICE_SECRET_BYTES),
        )
        credential.validate()
        return credential

    def export_secret_for_store(self) -> bytes:
        self.validate()
        return bytes(self.secret)


@dataclass(frozen=True)
class AgentSignedRequest:
    method: str
    path: str
    body: bytes = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)


@dataclass(frozen=True)
class VerifiedAgentRequest:
    device_id: str
    instance_id: str
    boot_id: str
    connection_epoch: int
    timestamp: datetime
    nonce: str
    body_sha256: str


@dataclass(frozen=True)
class AgentCommandEnvelope:
    schema_version: int
    request_id: str
    instance_id: str
    action: str
    params: Mapping[str, Any]
    deadline_at: datetime
    approved_command_sha256: str | None = None

    def validate(self) -> None:
        if self.schema_version != AGENT_TRANSPORT_SCHEMA_VERSION:
            raise AgentTransportError(
                f"unsupported Agent command schema: {self.schema_version}"
            )
        _validate_identifier(self.request_id, "request_id")
        _validate_identifier(self.instance_id, "instance_id")
        if self.action not in DEFAULT_REQUIRED_CAPABILITIES:
            raise AgentTransportError(f"unsupported Agent command action: {self.action}")
        _require_json_object(self.params, "params")
        _aware_utc(self.deadline_at, "deadline_at")
        if self.approved_command_sha256 is not None:
            _validate_sha256(self.approved_command_sha256, "approved_command_sha256")
            if not hmac.compare_digest(
                self.approved_command_sha256.lower(),
                self.command_sha256().lower(),
            ):
                raise AgentTransportError(
                    "approved command SHA-256 does not match exact command"
                )

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "instance_id": self.instance_id,
            "action": self.action,
            "params": dict(self.params),
            "deadline_at": _iso(self.deadline_at),
        }

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        payload = self.unsigned_dict()
        payload["approved_command_sha256"] = self.approved_command_sha256
        return payload

    def command_sha256(self) -> str:
        return hashlib.sha256(_canonical_json(self.unsigned_dict())).hexdigest()

    def is_destructive_approved(self) -> bool:
        self.validate()
        return self.approved_command_sha256 is not None


@dataclass(frozen=True)
class SignedAgentCommand:
    command: AgentCommandEnvelope
    signature: str = field(repr=False)

    def to_dict(self) -> dict[str, Any]:
        self.command.validate()
        _validate_signature_hex(self.signature)
        return {
            "command": self.command.to_dict(),
            "signature": self.signature,
        }


@dataclass(frozen=True)
class AgentCommandResult:
    schema_version: int
    request_id: str
    instance_id: str
    outcome: str
    response: Mapping[str, Any]
    completed_at: datetime

    def validate(self) -> None:
        if self.schema_version != AGENT_TRANSPORT_SCHEMA_VERSION:
            raise AgentTransportError(
                f"unsupported Agent result schema: {self.schema_version}"
            )
        _validate_identifier(self.request_id, "request_id")
        _validate_identifier(self.instance_id, "instance_id")
        if self.outcome not in {"ok", "failed", "denied", "error"}:
            raise AgentTransportError("unsupported Agent command result outcome")
        _require_json_object(self.response, "response")
        _aware_utc(self.completed_at, "completed_at")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "instance_id": self.instance_id,
            "outcome": self.outcome,
            "response": dict(self.response),
            "completed_at": _iso(self.completed_at),
        }


def _validate_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise AgentTransportError(f"{name} is invalid")
    if any(char not in _SAFE_IDENTIFIER_CHARS for char in value):
        raise AgentTransportError(f"{name} contains unsupported characters")


def _validate_nonce(value: str) -> None:
    if not isinstance(value, str) or not (20 <= len(value) <= 128):
        raise AgentTransportError("Agent request nonce is invalid")
    if any(char not in _SAFE_IDENTIFIER_CHARS for char in value):
        raise AgentTransportError("Agent request nonce contains unsupported characters")


def _validate_sha256(value: str, name: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise AgentTransportError(f"{name} must contain 64 hexadecimal characters")
    try:
        int(value, 16)
    except ValueError as exc:
        raise AgentTransportError(f"{name} must be hexadecimal") from exc


def _validate_signature_hex(value: str) -> None:
    _validate_sha256(value, "signature")


def _aware_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AgentTransportError(f"{name} must be timezone-aware")
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware_utc(value, "timestamp").isoformat().replace("+00:00", "Z")


def _parse_iso(value: str, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AgentAuthenticationError(f"{name} is required")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AgentAuthenticationError(f"{name} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentAuthenticationError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise AgentTransportError("payload must be canonical JSON-compatible") from exc
    return text.encode("utf-8")


def _require_json_object(value: Mapping[str, Any], name: str) -> None:
    if not isinstance(value, Mapping):
        raise AgentTransportError(f"{name} must be an object")
    _canonical_json(value)


def _validate_method_path(method: str, path: str) -> tuple[str, str]:
    if method != "POST":
        raise AgentTransportError("Agent transport supports POST only")
    if path not in ALLOWED_AGENT_ENDPOINTS:
        raise AgentTransportError(f"unsupported Agent transport endpoint: {path}")
    return method, path


def _body_sha256(body: bytes) -> str:
    if not isinstance(body, bytes):
        raise AgentTransportError("Agent request body must be bytes")
    if len(body) > MAX_AGENT_BODY_BYTES:
        raise AgentTransportError("Agent request body exceeds maximum size")
    return hashlib.sha256(body).hexdigest()


def _canonical_request(
    *,
    method: str,
    path: str,
    device_id: str,
    instance_id: str,
    boot_id: str,
    connection_epoch: int,
    timestamp: str,
    nonce: str,
    body_sha256: str,
) -> bytes:
    parts = (
        _AGENT_REQUEST_DOMAIN,
        method,
        path,
        device_id,
        instance_id,
        boot_id,
        str(connection_epoch),
        timestamp,
        nonce,
        body_sha256,
    )
    return "\n".join(parts).encode("utf-8")


def sign_agent_request(
    credential: AgentDeviceCredential,
    *,
    path: str,
    body: bytes,
    boot_id: str,
    connection_epoch: int,
    now: datetime | None = None,
    nonce: str | None = None,
) -> AgentSignedRequest:
    credential.validate()
    method, path = _validate_method_path("POST", path)
    _validate_identifier(boot_id, "boot_id")
    if not isinstance(connection_epoch, int) or isinstance(connection_epoch, bool) or connection_epoch < 1:
        raise AgentTransportError("connection_epoch must be a positive integer")
    timestamp_value = _aware_utc(now or datetime.now(timezone.utc), "now")
    timestamp = _iso(timestamp_value)
    nonce_value = nonce or secrets.token_urlsafe(AGENT_REQUEST_NONCE_BYTES)
    _validate_nonce(nonce_value)
    digest = _body_sha256(body)
    canonical = _canonical_request(
        method=method,
        path=path,
        device_id=credential.device_id,
        instance_id=credential.instance_id,
        boot_id=boot_id,
        connection_epoch=connection_epoch,
        timestamp=timestamp,
        nonce=nonce_value,
        body_sha256=digest,
    )
    signature = hmac.new(credential.secret, canonical, hashlib.sha256).hexdigest()
    headers = {
        "X-HMS-Agent-Schema": str(AGENT_TRANSPORT_SCHEMA_VERSION),
        "X-HMS-Device-Id": credential.device_id,
        "X-HMS-Instance-Id": credential.instance_id,
        "X-HMS-Boot-Id": boot_id,
        "X-HMS-Connection-Epoch": str(connection_epoch),
        "X-HMS-Timestamp": timestamp,
        "X-HMS-Nonce": nonce_value,
        "X-HMS-Content-SHA256": digest,
        "Authorization": f"{_AUTH_SCHEME} {signature}",
    }
    return AgentSignedRequest(method=method, path=path, body=body, headers=headers)


def verify_agent_request(
    credential: AgentDeviceCredential,
    signed: AgentSignedRequest,
    *,
    now: datetime | None = None,
) -> VerifiedAgentRequest:
    credential.validate()
    method, path = _validate_method_path(signed.method, signed.path)
    digest = _body_sha256(signed.body)
    headers = {str(key).casefold(): str(value) for key, value in signed.headers.items()}

    required = {
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
    missing = sorted(required.difference(headers))
    if missing:
        raise AgentAuthenticationError(
            "Agent request is missing authentication headers: " + ", ".join(missing)
        )
    if headers["x-hms-agent-schema"] != str(AGENT_TRANSPORT_SCHEMA_VERSION):
        raise AgentAuthenticationError("unsupported Agent transport schema")
    if headers["x-hms-device-id"] != credential.device_id:
        raise AgentAuthenticationError("Agent device_id mismatch")
    if headers["x-hms-instance-id"] != credential.instance_id:
        raise AgentAuthenticationError("Agent instance_id mismatch")

    boot_id = headers["x-hms-boot-id"]
    _validate_identifier(boot_id, "boot_id")
    try:
        connection_epoch = int(headers["x-hms-connection-epoch"])
    except ValueError as exc:
        raise AgentAuthenticationError("Agent connection epoch is invalid") from exc
    if connection_epoch < 1:
        raise AgentAuthenticationError("Agent connection epoch must be positive")

    timestamp_text = headers["x-hms-timestamp"]
    timestamp = _parse_iso(timestamp_text, "Agent timestamp")
    checked_at = _aware_utc(now or datetime.now(timezone.utc), "now")
    if abs(checked_at - timestamp) > timedelta(seconds=MAX_AGENT_CLOCK_SKEW_SECONDS):
        raise AgentClockSkewError("Agent request timestamp exceeds allowed clock skew")

    nonce = headers["x-hms-nonce"]
    _validate_nonce(nonce)
    header_digest = headers["x-hms-content-sha256"]
    _validate_sha256(header_digest, "X-HMS-Content-SHA256")
    if not hmac.compare_digest(header_digest.lower(), digest.lower()):
        raise AgentBodyIntegrityError("Agent request body SHA-256 mismatch")

    authorization = headers["authorization"]
    prefix = _AUTH_SCHEME + " "
    if not authorization.startswith(prefix):
        raise AgentAuthenticationError("Agent Authorization scheme is invalid")
    signature = authorization[len(prefix) :]
    _validate_signature_hex(signature)
    canonical = _canonical_request(
        method=method,
        path=path,
        device_id=credential.device_id,
        instance_id=credential.instance_id,
        boot_id=boot_id,
        connection_epoch=connection_epoch,
        timestamp=timestamp_text,
        nonce=nonce,
        body_sha256=header_digest,
    )
    expected = hmac.new(credential.secret, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature.lower()):
        raise AgentAuthenticationError("Agent request HMAC signature mismatch")

    return VerifiedAgentRequest(
        device_id=credential.device_id,
        instance_id=credential.instance_id,
        boot_id=boot_id,
        connection_epoch=connection_epoch,
        timestamp=timestamp,
        nonce=nonce,
        body_sha256=digest,
    )


def sign_bridge_command(
    credential: AgentDeviceCredential,
    command: AgentCommandEnvelope,
) -> SignedAgentCommand:
    credential.validate()
    command.validate()
    if command.instance_id != credential.instance_id:
        raise AgentTransportError("Bridge command targets another instance")
    payload = _canonical_json(command.to_dict())
    signature = hmac.new(
        credential.secret,
        _BRIDGE_COMMAND_DOMAIN.encode("utf-8") + b"\x00" + payload,
        hashlib.sha256,
    ).hexdigest()
    return SignedAgentCommand(command=command, signature=signature)


def verify_bridge_command(
    credential: AgentDeviceCredential,
    signed: SignedAgentCommand,
    *,
    now: datetime | None = None,
) -> AgentCommandEnvelope:
    credential.validate()
    signed.command.validate()
    _validate_signature_hex(signed.signature)
    if signed.command.instance_id != credential.instance_id:
        raise AgentAuthenticationError("Bridge command instance mismatch")
    payload = _canonical_json(signed.command.to_dict())
    expected = hmac.new(
        credential.secret,
        _BRIDGE_COMMAND_DOMAIN.encode("utf-8") + b"\x00" + payload,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, signed.signature.lower()):
        raise AgentAuthenticationError("Bridge command HMAC signature mismatch")
    checked_at = _aware_utc(now or datetime.now(timezone.utc), "now")
    deadline = _aware_utc(signed.command.deadline_at, "deadline_at")
    if checked_at >= deadline:
        raise AgentAuthenticationError("Bridge command deadline has expired")
    return signed.command
