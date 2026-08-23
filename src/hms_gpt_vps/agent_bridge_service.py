from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Callable, Mapping

from .agent_command_store import AgentCommandStatus, AgentCommandStore
from .agent_connection_registry import AgentConnectionRegistry, AgentPresence
from .agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES
from .agent_transport_codec import parse_agent_command_result
from .agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentAuthenticationError,
    AgentCommandEnvelope,
    AgentDeviceCredential,
    AgentSignedRequest,
    AgentTransportError,
    VerifiedAgentRequest,
    sign_bridge_command,
    verify_agent_request,
)


RequestCredentialResolver = Callable[[str, str], AgentDeviceCredential]
CommandCredentialResolver = Callable[[str], AgentDeviceCredential]


class AgentBridgeServiceError(RuntimeError):
    pass


def _aware_utc(value: datetime | None = None) -> datetime:
    checked = value or datetime.now(timezone.utc)
    if checked.tzinfo is None or checked.utcoffset() is None:
        raise AgentBridgeServiceError("Bridge Agent timestamp must be timezone-aware")
    return checked.astimezone(timezone.utc)


def _strict_json_object(data: bytes) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentTransportError("Agent request body is not valid UTF-8") from exc
    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, ValueError) as exc:
        raise AgentTransportError("Agent request body is not valid strict JSON") from exc
    if not isinstance(value, dict):
        raise AgentTransportError("Agent request body must be a JSON object")
    return value


def _require_exact_fields(
    value: Mapping[str, Any],
    expected: set[str],
    name: str,
) -> None:
    actual = set(value.keys())
    if actual != expected:
        raise AgentTransportError(f"{name} fields do not match schema")


def _require_schema(value: Any, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AgentTransportError(f"{name} schema_version must be an integer")
    if value != AGENT_TRANSPORT_SCHEMA_VERSION:
        raise AgentTransportError(f"unsupported {name} schema")


def _fold_headers(headers: Mapping[str, str]) -> dict[str, str]:
    folded: dict[str, str] = {}
    for key, value in headers.items():
        normalized = str(key).casefold()
        if normalized in folded:
            raise AgentAuthenticationError(
                "Agent request contains duplicate case-insensitive headers"
            )
        folded[normalized] = str(value)
    return folded


def _validate_capabilities(value: Any) -> None:
    if not isinstance(value, list) or not value:
        raise AgentTransportError("Agent capabilities must be a non-empty array")
    if any(not isinstance(item, str) or not item for item in value):
        raise AgentTransportError("Agent capabilities contain an invalid value")
    if len(set(value)) != len(value):
        raise AgentTransportError("Agent capabilities must be unique")
    if frozenset(value) != frozenset(DEFAULT_REQUIRED_CAPABILITIES):
        raise AgentTransportError(
            "Agent capabilities do not match the canonical capability set"
        )


class AgentBridgeService:
    """Authenticated Bridge router for the four fixed Agent endpoints.

    Ordering is security-critical: select the expected credential from untrusted
    identity headers, verify the HMAC/body/timestamp, strictly validate the
    authenticated endpoint payload, then mutate replay/presence state, and only
    then touch command/result state.
    """

    def __init__(
        self,
        registry: AgentConnectionRegistry,
        commands: AgentCommandStore,
        request_credential_resolver: RequestCredentialResolver,
        command_credential_resolver: CommandCredentialResolver,
    ) -> None:
        self.registry = registry
        self.commands = commands
        self.request_credential_resolver = request_credential_resolver
        self.command_credential_resolver = command_credential_resolver

    def _resolve_request_credential(
        self,
        signed: AgentSignedRequest,
    ) -> AgentDeviceCredential:
        headers = _fold_headers(signed.headers)
        instance_id = headers.get("x-hms-instance-id")
        device_id = headers.get("x-hms-device-id")
        if not instance_id or not device_id:
            raise AgentAuthenticationError(
                "Agent request is missing identity selector headers"
            )
        try:
            credential = self.request_credential_resolver(instance_id, device_id)
        except (KeyError, LookupError, FileNotFoundError):
            raise AgentAuthenticationError("Agent credential could not be resolved") from None
        if not isinstance(credential, AgentDeviceCredential):
            raise AgentBridgeServiceError(
                "request credential resolver returned an invalid credential"
            )
        credential.validate()
        return credential

    @staticmethod
    def _validate_common_identity(
        payload: Mapping[str, Any],
        verified: VerifiedAgentRequest,
        *,
        name: str,
    ) -> None:
        _require_schema(payload["schema_version"], name)
        if payload["instance_id"] != verified.instance_id:
            raise AgentTransportError(f"{name} instance_id mismatch")
        if payload["device_id"] != verified.device_id:
            raise AgentTransportError(f"{name} device_id mismatch")

    def _validate_endpoint_payload(
        self,
        path: str,
        payload: Mapping[str, Any],
        verified: VerifiedAgentRequest,
    ) -> None:
        if path == "/agent/v1/hello":
            _require_exact_fields(
                payload,
                {
                    "schema_version",
                    "instance_id",
                    "device_id",
                    "boot_id",
                    "connection_epoch",
                    "capabilities",
                },
                "Agent hello",
            )
            self._validate_common_identity(payload, verified, name="Agent hello")
            if payload["boot_id"] != verified.boot_id:
                raise AgentTransportError("Agent hello boot_id mismatch")
            if payload["connection_epoch"] != verified.connection_epoch:
                raise AgentTransportError("Agent hello connection_epoch mismatch")
            _validate_capabilities(payload["capabilities"])
            return

        if path == "/agent/v1/heartbeat":
            _require_exact_fields(
                payload,
                {
                    "schema_version",
                    "instance_id",
                    "device_id",
                    "boot_id",
                    "connection_epoch",
                    "status",
                    "capabilities",
                },
                "Agent heartbeat",
            )
            self._validate_common_identity(payload, verified, name="Agent heartbeat")
            if payload["boot_id"] != verified.boot_id:
                raise AgentTransportError("Agent heartbeat boot_id mismatch")
            if payload["connection_epoch"] != verified.connection_epoch:
                raise AgentTransportError("Agent heartbeat connection_epoch mismatch")
            if payload["status"] != "healthy":
                raise AgentTransportError("Agent heartbeat status must be healthy")
            _validate_capabilities(payload["capabilities"])
            return

        if path == "/agent/v1/poll":
            _require_exact_fields(
                payload,
                {
                    "schema_version",
                    "instance_id",
                    "device_id",
                    "wait_seconds",
                    "max_commands",
                },
                "Agent poll",
            )
            self._validate_common_identity(payload, verified, name="Agent poll")
            wait_seconds = payload["wait_seconds"]
            if (
                not isinstance(wait_seconds, int)
                or isinstance(wait_seconds, bool)
                or not 0 <= wait_seconds <= 30
            ):
                raise AgentTransportError(
                    "Agent poll wait_seconds must be an integer between 0 and 30"
                )
            if payload["max_commands"] != 1:
                raise AgentTransportError("Agent poll max_commands must equal 1")
            return

        if path == "/agent/v1/result":
            result = parse_agent_command_result(payload)
            if result.instance_id != verified.instance_id:
                raise AgentTransportError("Agent result instance_id mismatch")
            return

        raise AgentTransportError(f"unsupported Agent transport endpoint: {path}")

    @staticmethod
    def _identity_ack(presence: AgentPresence) -> dict[str, Any]:
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "accepted": True,
            "instance_id": presence.instance_id,
            "device_id": presence.device_id,
            "connection_epoch": presence.connection_epoch,
        }

    def handle(
        self,
        signed: AgentSignedRequest,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        checked_at = _aware_utc(now)
        credential = self._resolve_request_credential(signed)

        # HMAC/body hash/timestamp verification happens before JSON parsing or
        # any registry/queue mutation.
        verified = verify_agent_request(
            credential,
            signed,
            now=checked_at,
        )
        payload = _strict_json_object(signed.body)
        self._validate_endpoint_payload(signed.path, payload, verified)

        # Only authenticated + schema-valid requests may consume a nonce or
        # change the current connection epoch/presence.
        presence = self.registry.accept_verified_request(
            verified,
            now=checked_at,
        )

        if signed.path in {"/agent/v1/hello", "/agent/v1/heartbeat"}:
            return self._identity_ack(presence)

        if signed.path == "/agent/v1/poll":
            pending = self.commands.next_pending(
                verified.instance_id,
                now=checked_at,
            )
            return {
                "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
                "instance_id": verified.instance_id,
                "command": None if pending is None else pending.to_dict(),
            }

        if signed.path == "/agent/v1/result":
            result = parse_agent_command_result(payload)
            status = self.commands.complete(result, now=checked_at)
            if status.result is None:
                raise AgentBridgeServiceError(
                    "completed Agent result disappeared from command store"
                )
            return {
                "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
                "accepted": True,
                "instance_id": verified.instance_id,
                "request_id": result.request_id,
            }

        raise AgentTransportError(
            f"unsupported Agent transport endpoint: {signed.path}"
        )

    def enqueue_command(
        self,
        command: AgentCommandEnvelope,
        *,
        now: datetime | None = None,
    ) -> AgentCommandStatus:
        command.validate()
        try:
            credential = self.command_credential_resolver(command.instance_id)
        except (KeyError, LookupError, FileNotFoundError):
            raise AgentBridgeServiceError(
                "managed instance has no Agent device credential"
            ) from None
        if not isinstance(credential, AgentDeviceCredential):
            raise AgentBridgeServiceError(
                "command credential resolver returned an invalid credential"
            )
        credential.validate()
        if credential.instance_id != command.instance_id:
            raise AgentBridgeServiceError(
                "command credential belongs to another managed instance"
            )
        presence = self.registry.get_presence(command.instance_id)
        if presence is not None and presence.device_id != credential.device_id:
            raise AgentBridgeServiceError(
                "command credential conflicts with current Agent presence"
            )
        signed = sign_bridge_command(credential, command)
        return self.commands.enqueue(signed, now=_aware_utc(now))

    def get_command_status(
        self,
        instance_id: str,
        request_id: str,
    ) -> AgentCommandStatus | None:
        return self.commands.get_status(instance_id, request_id)
