from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentCommandResult,
    AgentTransportError,
    SignedAgentCommand,
)


def _require_exact_keys(
    value: Mapping[str, Any],
    *,
    expected: set[str],
    name: str,
) -> None:
    if not isinstance(value, Mapping):
        raise AgentTransportError(f"{name} must be an object")
    actual = {str(key) for key in value.keys()}
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail: list[str] = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("extra=" + ",".join(extra))
        suffix = " " + " ".join(detail) if detail else ""
        raise AgentTransportError(f"{name} fields do not match schema{suffix}")


def _parse_utc_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AgentTransportError(f"{name} must be a timestamp string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AgentTransportError(f"{name} is not a valid timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AgentTransportError(f"{name} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def parse_agent_command(value: Mapping[str, Any]) -> AgentCommandEnvelope:
    expected = {
        "schema_version",
        "request_id",
        "instance_id",
        "action",
        "params",
        "deadline_at",
        "approved_command_sha256",
    }
    _require_exact_keys(value, expected=expected, name="Agent command")
    schema_version = value["schema_version"]
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise AgentTransportError("Agent command schema_version must be an integer")
    params = value["params"]
    if not isinstance(params, Mapping):
        raise AgentTransportError("Agent command params must be an object")
    approved = value["approved_command_sha256"]
    if approved is not None and not isinstance(approved, str):
        raise AgentTransportError("approved_command_sha256 must be a string or null")
    command = AgentCommandEnvelope(
        schema_version=schema_version,
        request_id=value["request_id"],
        instance_id=value["instance_id"],
        action=value["action"],
        params=dict(params),
        deadline_at=_parse_utc_timestamp(value["deadline_at"], "deadline_at"),
        approved_command_sha256=approved,
    )
    command.validate()
    return command


def parse_signed_agent_command(value: Mapping[str, Any]) -> SignedAgentCommand:
    _require_exact_keys(
        value,
        expected={"command", "signature"},
        name="Signed Agent command",
    )
    raw_command = value["command"]
    if not isinstance(raw_command, Mapping):
        raise AgentTransportError("Signed Agent command.command must be an object")
    signature = value["signature"]
    if not isinstance(signature, str):
        raise AgentTransportError("Signed Agent command signature must be a string")
    signed = SignedAgentCommand(
        command=parse_agent_command(raw_command),
        signature=signature,
    )
    # to_dict performs signature shape validation without exposing it via repr.
    signed.to_dict()
    return signed


def parse_agent_command_result(value: Mapping[str, Any]) -> AgentCommandResult:
    _require_exact_keys(
        value,
        expected={
            "schema_version",
            "request_id",
            "instance_id",
            "outcome",
            "response",
            "completed_at",
        },
        name="Agent command result",
    )
    schema_version = value["schema_version"]
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise AgentTransportError("Agent result schema_version must be an integer")
    if schema_version != AGENT_TRANSPORT_SCHEMA_VERSION:
        raise AgentTransportError(f"unsupported Agent result schema: {schema_version}")
    response = value["response"]
    if not isinstance(response, Mapping):
        raise AgentTransportError("Agent result response must be an object")
    result = AgentCommandResult(
        schema_version=schema_version,
        request_id=value["request_id"],
        instance_id=value["instance_id"],
        outcome=value["outcome"],
        response=dict(response),
        completed_at=_parse_utc_timestamp(value["completed_at"], "completed_at"),
    )
    result.validate()
    return result
