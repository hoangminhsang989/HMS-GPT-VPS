from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Mapping

from .agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES
from .agent_https_client import AgentHttpsClient
from .agent_transport_codec import (
    parse_agent_command_result,
    parse_signed_agent_command,
)
from .agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentCommandResult,
    AgentTransportError,
    _canonical_json,
    verify_bridge_command,
)
from .idempotency_store import (
    IdempotencyInProgressError,
    IdempotencyStore,
)


class AgentRuntimeSessionError(RuntimeError):
    pass


class AgentRuntimeRejectedError(AgentRuntimeSessionError):
    pass


class AgentCommandAmbiguousError(AgentRuntimeSessionError):
    pass


@dataclass(frozen=True)
class AgentExecutionResponse:
    outcome: str
    response: Mapping[str, Any]

    def validate(self) -> None:
        if self.outcome not in {"ok", "failed", "denied", "error"}:
            raise AgentRuntimeSessionError("unsupported Agent execution outcome")
        if not isinstance(self.response, Mapping):
            raise AgentRuntimeSessionError("Agent execution response must be an object")
        _canonical_json(self.response)


@dataclass(frozen=True)
class AgentRuntimeSessionConfig:
    poll_wait_seconds: int = 20
    capabilities: tuple[str, ...] = tuple(sorted(DEFAULT_REQUIRED_CAPABILITIES))

    def validate(self) -> None:
        if not isinstance(self.poll_wait_seconds, int) or isinstance(self.poll_wait_seconds, bool):
            raise ValueError("poll_wait_seconds must be an integer")
        if not 0 <= self.poll_wait_seconds <= 30:
            raise ValueError("poll_wait_seconds must be between 0 and 30")
        if not self.capabilities or len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError("capabilities must be non-empty and unique")
        if frozenset(self.capabilities) != frozenset(DEFAULT_REQUIRED_CAPABILITIES):
            raise ValueError("runtime capabilities must match the current canonical Agent set")


CommandExecutor = Callable[[AgentCommandEnvelope], AgentExecutionResponse]


def _require_exact_fields(
    value: Mapping[str, Any],
    expected: set[str],
    name: str,
) -> None:
    if not isinstance(value, Mapping):
        raise AgentRuntimeSessionError(f"{name} must be an object")
    actual = set(value.keys())
    if actual != expected:
        raise AgentRuntimeSessionError(f"{name} fields do not match schema")


def _require_schema(value: Any, name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AgentRuntimeSessionError(f"{name} schema_version must be an integer")
    if value != AGENT_TRANSPORT_SCHEMA_VERSION:
        raise AgentRuntimeSessionError(f"unsupported {name} schema")


def _aware_utc(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("runtime timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class AgentRuntimeSession:
    """One authenticated Agent connection generation.

    The Bridge command is signature/deadline verified before the local durable
    idempotency claim. A new claim is persisted before execution. COMPLETED is
    persisted before the result is sent to the Bridge, so a lost result ACK can
    resend the cached result without repeating the side effect. A crash after
    CLAIMED but before COMPLETED remains ambiguous and automatic replay is
    blocked rather than executing the command again.
    """

    def __init__(
        self,
        http: AgentHttpsClient,
        idempotency: IdempotencyStore,
        executor: CommandExecutor,
        *,
        config: AgentRuntimeSessionConfig | None = None,
    ) -> None:
        self.http = http
        self.idempotency = idempotency
        self.executor = executor
        self.config = config or AgentRuntimeSessionConfig()
        self.config.validate()
        self._idempotency_namespace = hashlib.sha256(
            (
                "hms-agent-command/v1\x00"
                + self.http.credential.instance_id
                + "\x00"
                + self.http.credential.device_id
            ).encode("utf-8")
        ).hexdigest()

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "instance_id": self.http.credential.instance_id,
            "device_id": self.http.credential.device_id,
            "boot_id": self.http.boot_id,
            "connection_epoch": self.http.connection_epoch,
        }

    def _validate_identity_ack(self, response: Mapping[str, Any], name: str) -> None:
        _require_exact_fields(
            response,
            {
                "schema_version",
                "accepted",
                "instance_id",
                "device_id",
                "connection_epoch",
            },
            name,
        )
        _require_schema(response["schema_version"], name)
        if not isinstance(response["accepted"], bool):
            raise AgentRuntimeSessionError(f"{name}.accepted must be boolean")
        if response["instance_id"] != self.http.credential.instance_id:
            raise AgentRuntimeSessionError(f"{name} instance_id mismatch")
        if response["device_id"] != self.http.credential.device_id:
            raise AgentRuntimeSessionError(f"{name} device_id mismatch")
        if response["connection_epoch"] != self.http.connection_epoch:
            raise AgentRuntimeSessionError(f"{name} connection_epoch mismatch")
        if response["accepted"] is not True:
            raise AgentRuntimeRejectedError(f"{name} was rejected by Bridge")

    def hello(self) -> None:
        payload = self._identity_payload()
        payload["capabilities"] = list(self.config.capabilities)
        response = self.http.hello(payload)
        self._validate_identity_ack(response, "Agent hello")

    def heartbeat(self) -> None:
        payload = self._identity_payload()
        payload["status"] = "healthy"
        payload["capabilities"] = list(self.config.capabilities)
        response = self.http.heartbeat(payload)
        self._validate_identity_ack(response, "Agent heartbeat")

    def _validate_result_ack(self, response: Mapping[str, Any], request_id: str) -> None:
        _require_exact_fields(
            response,
            {"schema_version", "accepted", "instance_id", "request_id"},
            "Agent result ACK",
        )
        _require_schema(response["schema_version"], "Agent result ACK")
        if not isinstance(response["accepted"], bool):
            raise AgentRuntimeSessionError("Agent result ACK.accepted must be boolean")
        if response["instance_id"] != self.http.credential.instance_id:
            raise AgentRuntimeSessionError("Agent result ACK instance_id mismatch")
        if response["request_id"] != request_id:
            raise AgentRuntimeSessionError("Agent result ACK request_id mismatch")
        if response["accepted"] is not True:
            raise AgentRuntimeRejectedError("Agent result was rejected by Bridge")

    def _execute_new_command(
        self,
        command: AgentCommandEnvelope,
        *,
        completed_at: datetime,
    ) -> AgentCommandResult:
        try:
            execution = self.executor(command)
            if not isinstance(execution, AgentExecutionResponse):
                raise AgentRuntimeSessionError(
                    "command executor must return AgentExecutionResponse"
                )
            execution.validate()
        except PermissionError:
            execution = AgentExecutionResponse(
                outcome="denied",
                response={"error": "command denied"},
            )
        except Exception as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            execution = AgentExecutionResponse(
                outcome="error",
                response={"error": "command execution failed"},
            )
        result = AgentCommandResult(
            schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
            request_id=command.request_id,
            instance_id=command.instance_id,
            outcome=execution.outcome,
            response=dict(execution.response),
            completed_at=completed_at,
        )
        result.validate()
        return result

    def poll_once(self, *, now: datetime | None = None) -> AgentCommandResult | None:
        checked_at = _aware_utc(now)
        poll_response = self.http.poll(
            {
                "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
                "instance_id": self.http.credential.instance_id,
                "device_id": self.http.credential.device_id,
                "wait_seconds": self.config.poll_wait_seconds,
                "max_commands": 1,
            },
            now=checked_at,
        )
        _require_exact_fields(
            poll_response,
            {"schema_version", "instance_id", "command"},
            "Agent poll response",
        )
        _require_schema(poll_response["schema_version"], "Agent poll response")
        if poll_response["instance_id"] != self.http.credential.instance_id:
            raise AgentRuntimeSessionError("Agent poll response instance_id mismatch")
        raw_command = poll_response["command"]
        if raw_command is None:
            return None
        if not isinstance(raw_command, Mapping):
            raise AgentRuntimeSessionError("Agent poll command must be an object or null")

        signed = parse_signed_agent_command(raw_command)
        command = verify_bridge_command(
            self.http.credential,
            signed,
            now=checked_at,
        )
        command_identity_sha256 = hashlib.sha256(
            _canonical_json(command.to_dict())
        ).hexdigest()

        try:
            claim = self.idempotency.claim(
                self._idempotency_namespace,
                command.request_id,
                command_identity_sha256,
                now=checked_at,
            )
        except IdempotencyInProgressError as exc:
            raise AgentCommandAmbiguousError(
                "Agent command has an unresolved prior claim; automatic replay is blocked"
            ) from exc

        if claim.is_new:
            result = self._execute_new_command(
                command,
                completed_at=_aware_utc(),
            )
            cached = self.idempotency.complete(
                self._idempotency_namespace,
                command.request_id,
                command_identity_sha256,
                result.to_dict(),
                now=result.completed_at,
            )
            result = parse_agent_command_result(cached)
        else:
            if claim.replay_response is None:
                raise AgentRuntimeSessionError("completed Agent command cache is missing")
            result = parse_agent_command_result(claim.replay_response)
            if result.request_id != command.request_id:
                raise AgentRuntimeSessionError("cached Agent result request_id mismatch")
            if result.instance_id != command.instance_id:
                raise AgentRuntimeSessionError("cached Agent result instance_id mismatch")

        ack = self.http.submit_result(result.to_dict())
        self._validate_result_ack(ack, command.request_id)
        return result
