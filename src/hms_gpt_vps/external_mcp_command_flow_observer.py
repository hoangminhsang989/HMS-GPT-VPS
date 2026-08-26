from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
from pathlib import Path
from typing import Callable

from .control_request import CONTROL_REQUEST_SCHEMA_VERSION, ControlRequest
from .control_session import ControlSessionRecord
from .external_mcp_command_flow_contract import (
    EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION,
    ExternalMcpCommandFlowObservationError,
    ExternalMcpReadChallenge,
    READ_ACTION,
    READ_RESPONSE_FIELDS,
    RECEIPT_FIELDS,
    aware_utc,
    canonical_json_sha256,
    canonical_sha256,
)
from .external_mcp_command_flow_sqlite import (
    load_completed_agent_command,
    load_dispatch_and_receipt,
    load_pairing_and_control_session,
)
from .principal_binding_registry_authority import PinnedDpapiPrincipalBindingRegistry
from .principal_dispatch_intent import PrincipalDispatchIntent
from .principal_pairing_service import PrincipalSessionBinding
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
    require_existing_directory,
)


__all__ = [
    "EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION",
    "ExternalMcpCommandFlowObservationError",
    "ExternalMcpReadChallenge",
    "observe_external_mcp_read_durable_authority",
]


def _default_binding_loader(
    binding_root: Path,
    principal_sha256: str,
    instance_id: str,
) -> PrincipalSessionBinding | None:
    return (
        PinnedDpapiPrincipalBindingRegistry(binding_root)
        .store_for(principal_sha256, instance_id)
        .load()
    )


def _validate_binding_chain(
    binding: PrincipalSessionBinding,
    intent: PrincipalDispatchIntent,
    session: ControlSessionRecord,
    *,
    observed_at: datetime,
) -> None:
    try:
        binding.validate()
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "principal binding failed exact validation"
        ) from exc
    if (
        binding.principal_sha256 != intent.principal_sha256
        or binding.instance_id != intent.instance_id
        or binding.pair_id != intent.pair_id
        or binding.session_id != intent.session_id
        or binding.family_id != session.family_id
        or binding.session_token_sha256 != session.token_sha256
        or binding.scopes != session.scopes
        or binding.issued_at != session.issued_at
        or binding.expires_at != session.expires_at
        or binding.epoch != intent.session_epoch
        or binding.epoch != session.epoch
        or intent.expires_at != binding.expires_at
        or READ_ACTION not in binding.scopes
    ):
        raise ExternalMcpCommandFlowObservationError(
            "principal binding, control session, and dispatch intent differ"
        )
    if observed_at < binding.issued_at or observed_at >= binding.expires_at:
        raise ExternalMcpCommandFlowObservationError(
            "principal control session is not active at observation time"
        )


def _validate_read_result(
    response: object,
    challenge: ExternalMcpReadChallenge,
) -> tuple[int, str]:
    if not isinstance(response, dict) or frozenset(response) != READ_RESPONSE_FIELDS:
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read response fields do not match qualification schema"
        )
    if response["ok"] is not True or response["path"] != challenge.path:
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read response identity differs from challenge"
        )
    encoding = response["encoding"]
    content = response["content"]
    if encoding not in {"utf-8", "base64"} or not isinstance(content, str):
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read response encoding/content is invalid"
        )
    if encoding == "utf-8":
        data = content.encode("utf-8")
    else:
        try:
            data = base64.b64decode(content, validate=True)
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                "workspace.read base64 content is invalid"
            ) from exc
        if base64.b64encode(data).decode("ascii") != content:
            raise ExternalMcpCommandFlowObservationError(
                "workspace.read base64 content is not canonical"
            )
    size = response["size"]
    if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size != len(data):
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read response size differs from content bytes"
        )
    digest = canonical_sha256(response["sha256"], "workspace.read sha256")
    actual = hashlib.sha256(data).hexdigest()
    if (
        digest != actual
        or not hmac.compare_digest(digest, challenge.expected_content_sha256)
    ):
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read content SHA-256 differs from challenge authority"
        )
    modified = response["modified_utc"]
    if not isinstance(modified, str) or not modified:
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read modified_utc is invalid"
        )
    try:
        parsed = datetime.fromisoformat(modified)
    except ValueError as exc:
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read modified_utc is not a timestamp"
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.astimezone(timezone.utc).isoformat() != modified
    ):
        raise ExternalMcpCommandFlowObservationError(
            "workspace.read modified_utc is not canonical UTC"
        )
    return size, encoding


def _validate_receipt(
    receipt: dict[str, object],
    *,
    challenge: ExternalMcpReadChallenge,
    command_sha256: str,
    result_sha256: str,
) -> None:
    if frozenset(receipt) != RECEIPT_FIELDS:
        raise ExternalMcpCommandFlowObservationError(
            "principal completion receipt fields do not match schema"
        )
    schema = receipt["schema_version"]
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != 1:
        raise ExternalMcpCommandFlowObservationError(
            "principal completion receipt schema is invalid"
        )
    if (
        receipt["kind"] != "agent_completed"
        or receipt["instance_id"] != challenge.instance_id
        or receipt["request_id"] != challenge.request_id
        or receipt["command_sha256"] != command_sha256
        or receipt["result_sha256"] != result_sha256
    ):
        raise ExternalMcpCommandFlowObservationError(
            "principal completion receipt differs from exact Agent authority"
        )


def observe_external_mcp_read_durable_authority(
    runtime_root: Path,
    challenge: ExternalMcpReadChallenge,
    *,
    binding_loader: Callable[[Path, str, str], PrincipalSessionBinding | None] | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Observe an already-executed principal-bound read without creating work.

    This function never issues a pairing link, never submits or polls an MCP tool,
    never constructs an Agent command, and opens all SQLite authorities read-only.
    It proves the durable principal/session/dispatch/Agent chain for one challenge.
    It deliberately cannot prove that the initiating request originated from the
    OpenAI control plane or traversed one exact live tunnel generation; the later
    composite runner must bracket this observer with those live authorities.
    """

    if not isinstance(challenge, ExternalMcpReadChallenge):
        raise TypeError("challenge must be an ExternalMcpReadChallenge")
    challenge.validate()
    observed_at = aware_utc(now or datetime.now(timezone.utc), "observation time")
    if observed_at < challenge.issued_at or observed_at >= challenge.expires_at:
        raise ExternalMcpCommandFlowObservationError(
            "external MCP read challenge is not active at observation time"
        )
    if not isinstance(runtime_root, Path):
        raise TypeError("runtime_root must be a pathlib.Path")
    root = lexical_absolute(runtime_root)
    if path_chain_has_redirect(root):
        raise ExternalMcpCommandFlowObservationError(
            "Bridge runtime root traverses a link or reparse point"
        )
    try:
        root = require_existing_directory(root, label="Bridge runtime root")
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "Bridge runtime root authority is unavailable"
        ) from exc

    db_dir = root / "db"
    secrets_dir = root / "secrets"
    binding_root = secrets_dir / "principal-bindings"
    for path, label in (
        (db_dir, "Bridge runtime db directory"),
        (secrets_dir, "Bridge runtime secrets directory"),
        (binding_root, "principal binding root"),
    ):
        try:
            require_existing_directory(path, label=label)
        except Exception as exc:
            raise ExternalMcpCommandFlowObservationError(
                f"{label} authority is unavailable"
            ) from exc

    idempotency_db = db_dir / "control-idempotency.sqlite3"
    auth_db = db_dir / "pairing-control.sqlite3"
    command_db = db_dir / "agent-commands.sqlite3"

    intent, receipt = load_dispatch_and_receipt(idempotency_db, challenge)
    if intent.instance_id != challenge.instance_id or intent.request_id != challenge.request_id:
        raise ExternalMcpCommandFlowObservationError(
            "principal dispatch identity differs from challenge"
        )
    request = ControlRequest(
        schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
        request_id=challenge.request_id,
        instance_id=challenge.instance_id,
        session_id=intent.session_id,
        action=READ_ACTION,
        params={"path": challenge.path},
    )
    if request.request_sha256() != intent.request_sha256:
        raise ExternalMcpCommandFlowObservationError(
            "principal dispatch request digest differs from exact challenge"
        )

    pairing, session = load_pairing_and_control_session(auth_db, intent)
    loader = binding_loader or _default_binding_loader
    try:
        binding = loader(binding_root, intent.principal_sha256, challenge.instance_id)
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "principal binding authority could not be loaded"
        ) from exc
    if not isinstance(binding, PrincipalSessionBinding):
        raise ExternalMcpCommandFlowObservationError(
            "principal binding loader returned an invalid authority type"
        )
    _validate_binding_chain(binding, intent, session, observed_at=observed_at)
    if pairing.pair_id != binding.pair_id:
        raise ExternalMcpCommandFlowObservationError(
            "pairing record and principal binding differ"
        )

    signed, result = load_completed_agent_command(command_db, challenge)
    command = signed.command
    if (
        command.instance_id != challenge.instance_id
        or command.request_id != challenge.request_id
        or command.action != READ_ACTION
        or dict(command.params) != {"path": challenge.path}
        or command.approved_command_sha256 is not None
        or command.deadline_at != binding.expires_at
    ):
        raise ExternalMcpCommandFlowObservationError(
            "signed Agent command differs from exact read challenge authority"
        )
    command_sha256 = canonical_json_sha256(command.to_dict())
    if command_sha256 != intent.command_sha256:
        raise ExternalMcpCommandFlowObservationError(
            "principal dispatch command digest differs from signed Agent command"
        )

    result.validate()
    if (
        result.instance_id != challenge.instance_id
        or result.request_id != challenge.request_id
        or result.outcome != "ok"
    ):
        raise ExternalMcpCommandFlowObservationError(
            "Agent result identity/outcome differs from read challenge"
        )
    content_size, content_encoding = _validate_read_result(dict(result.response), challenge)
    result_sha256 = canonical_json_sha256(result.to_dict())
    _validate_receipt(
        receipt,
        challenge=challenge,
        command_sha256=command_sha256,
        result_sha256=result_sha256,
    )

    pairing_after, session_after = load_pairing_and_control_session(auth_db, intent)
    if pairing_after != pairing or session_after != session:
        raise ExternalMcpCommandFlowObservationError(
            "pairing or control-session authority changed during observation"
        )
    try:
        binding_after = loader(binding_root, intent.principal_sha256, challenge.instance_id)
    except Exception as exc:
        raise ExternalMcpCommandFlowObservationError(
            "principal binding authority could not be re-observed"
        ) from exc
    if not isinstance(binding_after, PrincipalSessionBinding):
        raise ExternalMcpCommandFlowObservationError(
            "principal binding re-observation returned an invalid authority type"
        )
    _validate_binding_chain(
        binding_after,
        intent,
        session_after,
        observed_at=observed_at,
    )

    return {
        "ready": True,
        "status": "PRINCIPAL_BOUND_READ_DURABLE_AUTHORITY_OBSERVED",
        "challenge_id": challenge.challenge_id,
        "source_commit": challenge.source_commit,
        "instance_id": challenge.instance_id,
        "request_id": challenge.request_id,
        "path": challenge.path,
        "expected_content_sha256": challenge.expected_content_sha256,
        "workspace_content_size": content_size,
        "workspace_content_encoding": content_encoding,
        "principal_sha256": intent.principal_sha256,
        "pair_id": intent.pair_id,
        "session_id": intent.session_id,
        "session_epoch": intent.session_epoch,
        "agent_command_action": command.action,
        "agent_result_outcome": result.outcome,
        "agent_result_sha256": result_sha256,
        "pairing_record_consumed": True,
        "principal_binding_proven": True,
        "control_session_proven": True,
        "dispatch_intent_proven": True,
        "idempotency_completion_receipt_proven": True,
        "agent_command_result_proven": True,
        "authenticated_principal_control_path_proven": True,
        "mcp_adapter_invocation_proven": False,
        "openai_control_plane_origin_proven": False,
        "secure_tunnel_generation_proven": False,
        "full_bridge_command_flow_proven": False,
    }
