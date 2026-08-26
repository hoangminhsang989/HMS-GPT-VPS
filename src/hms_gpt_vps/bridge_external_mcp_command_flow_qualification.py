from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import math
import secrets
import time
from typing import Callable

from .bridge_agent_transport_qualification import (
    BridgeAgentTransportQualificationError,
    _load_and_verify_package,
    _observe_guest_agent,
    _read_presence_read_only,
    _wait_for_authenticated_hello,
    _wait_for_heartbeat_generation_stability,
    start_hms_bridge_for_qualification,
    stop_hms_bridge_after_qualification,
)
from .bridge_composite_activation_qualification import _require_same_tunnel_generation
from .bridge_host_deployment_transaction import derive_hms_bridge_service_sid
from .bridge_service_config_storage import load_protected_bridge_service_runtime_config
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .external_mcp_command_flow_contract import (
    EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION,
    MAX_EXTERNAL_MCP_READ_CHALLENGE_SECONDS,
    ExternalMcpCommandFlowObservationError,
    ExternalMcpReadChallenge,
    canonical_git_sha1,
    canonical_sha256,
    qualification_path,
)
from .external_mcp_command_flow_observer import observe_external_mcp_read_durable_authority
from .external_mcp_command_flow_sqlite import read_only_connection, query_rows
from .idempotency_store import IdempotencyState, IdempotencyStore
from .powershell_direct import PowerShellDirectCredential
from .principal_dispatch_intent import PrincipalDispatchIntent
from .qualification_file_authority import write_json_create_only
from .secure_mcp_tunnel_native_qualification import qualify_running_secure_mcp_tunnel

_DEFAULT_EXTERNAL_TIMEOUT_SECONDS = 300.0
_MIN_EXTERNAL_TIMEOUT_SECONDS = 30.0
_POLL_INTERVAL_SECONDS = 0.25
_CHALLENGE_PREFIX = "r002fext"
_CHALLENGE_FILE_SCHEMA_VERSION = 1
_MAX_CHALLENGE_FILE_BYTES = 32 * 1024
_PROGRESS_ABSENT = "absent"
_PROGRESS_CLAIMED = "claimed"
_PROGRESS_COMPLETED = "completed"


class BridgeExternalMcpCommandFlowQualificationError(
    BridgeAgentTransportQualificationError
):
    pass


@dataclass(frozen=True)
class BridgeExternalMcpCommandFlowQualificationRequest:
    guest_credential: PowerShellDirectCredential
    source_commit: str
    path: str
    expected_content_sha256: str
    challenge_path: Path
    external_timeout_seconds: float = _DEFAULT_EXTERNAL_TIMEOUT_SECONDS
    hello_timeout_seconds: float = 45.0
    heartbeat_margin_seconds: float = 3.0

    def validate(self) -> None:
        if not isinstance(self.guest_credential, PowerShellDirectCredential):
            raise TypeError("guest_credential must be a PowerShellDirectCredential")
        self.guest_credential.validate()
        canonical_git_sha1(self.source_commit)
        qualification_path(self.path)
        canonical_sha256(self.expected_content_sha256, "expected_content_sha256")
        if not isinstance(self.challenge_path, Path):
            raise TypeError("challenge_path must be pathlib.Path")
        for name, value, lower, upper in (
            (
                "external_timeout_seconds",
                self.external_timeout_seconds,
                _MIN_EXTERNAL_TIMEOUT_SECONDS,
                float(MAX_EXTERNAL_MCP_READ_CHALLENGE_SECONDS),
            ),
            ("hello_timeout_seconds", self.hello_timeout_seconds, 5.0, 120.0),
            ("heartbeat_margin_seconds", self.heartbeat_margin_seconds, 1.0, 30.0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not lower <= float(value) <= upper
            ):
                raise ValueError(f"{name} is outside qualification bounds")


def _require_stopped_manual(
    evidence: dict[str, object],
    *,
    service_sid: str,
    phase: str,
) -> None:
    if (
        not isinstance(evidence, dict)
        or evidence.get("service_sid") != service_sid
        or evidence.get("service_state") != "Stopped"
        or evidence.get("service_start_mode") != "Manual"
    ):
        raise BridgeExternalMcpCommandFlowQualificationError(
            f"HMSBridge is not exact Stopped/Manual at {phase}"
        )


def _new_challenge(
    request: BridgeExternalMcpCommandFlowQualificationRequest,
    *,
    instance_id: str,
    now: datetime | None = None,
) -> ExternalMcpReadChallenge:
    issued_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    challenge = ExternalMcpReadChallenge(
        schema_version=EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION,
        challenge_id=f"{_CHALLENGE_PREFIX}-challenge-{secrets.token_urlsafe(12)}",
        source_commit=request.source_commit,
        instance_id=instance_id,
        request_id=f"{_CHALLENGE_PREFIX}-request-{secrets.token_urlsafe(12)}",
        path=request.path,
        expected_content_sha256=request.expected_content_sha256,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=float(request.external_timeout_seconds)),
    )
    challenge.validate()
    return challenge


def _canonical_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _challenge_payload(challenge: ExternalMcpReadChallenge) -> dict[str, object]:
    challenge.validate()
    return {
        "schema_version": _CHALLENGE_FILE_SCHEMA_VERSION,
        "kind": "R002F_EXTERNAL_MCP_READ_CHALLENGE",
        "tool_name": "read_file",
        "challenge": {
            "schema_version": challenge.schema_version,
            "challenge_id": challenge.challenge_id,
            "source_commit": challenge.source_commit,
            "instance_id": challenge.instance_id,
            "request_id": challenge.request_id,
            "path": challenge.path,
            "expected_content_sha256": challenge.expected_content_sha256,
            "issued_at": _canonical_utc(challenge.issued_at),
            "expires_at": _canonical_utc(challenge.expires_at),
        },
        "tool_arguments": {
            "instance_id": challenge.instance_id,
            "request_id": challenge.request_id,
            "path": challenge.path,
        },
        "non_secret": True,
    }


def _observe_external_progress(
    runtime_root: Path,
    challenge: ExternalMcpReadChallenge,
) -> str:
    challenge.validate()
    idempotency_db = runtime_root / "db" / "control-idempotency.sqlite3"
    with read_only_connection(
        idempotency_db,
        label="external MCP progress authority database",
    ) as connection:
        dispatch_rows = query_rows(
            connection,
            """
            SELECT schema_version, principal_sha256, pair_id, session_id,
                   session_epoch, instance_id, request_id, request_sha256,
                   command_sha256, expires_at
            FROM principal_agent_dispatch_claims
            WHERE instance_id = ? AND request_id = ?
            """,
            (challenge.instance_id, challenge.request_id),
        )
        if not dispatch_rows:
            return _PROGRESS_ABSENT
        if len(dispatch_rows) != 1:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "external challenge resolved to duplicate principal dispatch rows"
            )
        try:
            intent = PrincipalDispatchIntent.from_row(dispatch_rows[0])
        except Exception as exc:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "external principal dispatch progress authority is invalid"
            ) from exc
        if (
            intent.instance_id != challenge.instance_id
            or intent.request_id != challenge.request_id
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "external principal dispatch progress identity differs"
            )
        idempotency_rows = query_rows(
            connection,
            """
            SELECT request_sha256, state, response_json, response_sha256,
                   claimed_at, completed_at
            FROM idempotency_records
            WHERE session_id = ? AND request_id = ?
            """,
            (intent.session_id, intent.request_id),
        )
        if len(idempotency_rows) != 1:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "external principal dispatch lacks one atomic idempotency row"
            )
        try:
            state, _ = IdempotencyStore._validate_row(
                idempotency_rows[0],
                expected_request_sha256=intent.request_sha256,
            )
        except Exception as exc:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "external idempotency progress authority is invalid"
            ) from exc
    if state is IdempotencyState.CLAIMED:
        return _PROGRESS_CLAIMED
    if state is IdempotencyState.COMPLETED:
        return _PROGRESS_COMPLETED
    raise BridgeExternalMcpCommandFlowQualificationError(
        "external idempotency progress state is unsupported"
    )


def _wait_for_external_observation(
    runtime_root: Path,
    challenge: ExternalMcpReadChallenge,
    *,
    timeout_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, object]:
    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        progress = _observe_external_progress(runtime_root, challenge)
        if progress == _PROGRESS_COMPLETED:
            try:
                return observe_external_mcp_read_durable_authority(
                    runtime_root,
                    challenge,
                )
            except ExternalMcpCommandFlowObservationError as exc:
                raise BridgeExternalMcpCommandFlowQualificationError(
                    "completed external MCP read failed durable authority observation"
                ) from exc
        if progress not in {_PROGRESS_ABSENT, _PROGRESS_CLAIMED}:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "external MCP progress returned an invalid state"
            )
        sleeper(_POLL_INTERVAL_SECONDS)
    raise BridgeExternalMcpCommandFlowQualificationError(
        "external MCP read was not durably completed before timeout"
    )


def _require_observer_success(
    evidence: dict[str, object],
    challenge: ExternalMcpReadChallenge,
) -> None:
    if not isinstance(evidence, dict):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "external MCP observer returned invalid evidence"
        )
    challenge.validate()
    expected_identity = {
        "challenge_id": challenge.challenge_id,
        "source_commit": challenge.source_commit,
        "instance_id": challenge.instance_id,
        "request_id": challenge.request_id,
        "path": challenge.path,
        "expected_content_sha256": challenge.expected_content_sha256,
    }
    for key, wanted in expected_identity.items():
        if evidence.get(key) != wanted:
            raise BridgeExternalMcpCommandFlowQualificationError(
                f"external MCP observer identity differs: {key}"
            )
    for key in (
        "ready",
        "pairing_record_consumed",
        "principal_binding_proven",
        "control_session_proven",
        "dispatch_intent_proven",
        "idempotency_completion_receipt_proven",
        "agent_command_result_proven",
        "authenticated_principal_control_path_proven",
    ):
        if evidence.get(key) is not True:
            raise BridgeExternalMcpCommandFlowQualificationError(
                f"external MCP observer did not prove {key}"
            )
    for key in (
        "mcp_adapter_invocation_proven",
        "openai_control_plane_origin_proven",
        "secure_tunnel_generation_proven",
        "full_bridge_command_flow_proven",
    ):
        if evidence.get(key) is not False:
            raise BridgeExternalMcpCommandFlowQualificationError(
                f"external MCP observer escaped its proof boundary: {key}"
            )


def qualify_external_mcp_read_with_stable_tunnel(
    request: BridgeExternalMcpCommandFlowQualificationRequest,
) -> dict[str, object]:
    """Bracket one externally-issued principal read with one live tunnel/Agent generation.

    The runner publishes only a non-secret challenge. It never invokes MCP, never
    constructs a principal, and never enqueues an Agent command. A successful run
    therefore proves an externally coordinated durable principal read occurred
    while one reviewed HMSBridge/tunnel/Agent generation stayed stable. It does
    not by itself prove the initiating caller was the OpenAI control plane.
    """

    if not isinstance(request, BridgeExternalMcpCommandFlowQualificationRequest):
        raise TypeError(
            "request must be BridgeExternalMcpCommandFlowQualificationRequest"
        )
    request.validate()
    service_sid = derive_hms_bridge_service_sid()
    config = load_protected_bridge_service_runtime_config()
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "protected Bridge runtime config type is invalid"
        )
    config.validate()
    config.to_runtime_config(service_sid)
    manifest = _load_and_verify_package()
    pre = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual(
        pre,
        service_sid=service_sid,
        phase="external MCP qualification start",
    )

    guest_before = _observe_guest_agent(config, request.guest_credential)
    presence_path = Path(config.runtime_root) / "db" / "agent-presence.sqlite3"
    started_at_unix = datetime.now(timezone.utc).timestamp()
    started = False
    primary_error: BaseException | None = None
    start_evidence: dict[str, object] | None = None
    stop_evidence: dict[str, object] | None = None
    tunnel_before: dict[str, object] | None = None
    tunnel_after: dict[str, object] | None = None
    observer: dict[str, object] | None = None
    challenge: ExternalMcpReadChallenge | None = None
    hello = None
    heartbeat = None
    try:
        start_evidence = start_hms_bridge_for_qualification(
            config,
            manifest,
            service_sid,
        )
        started = True
        service_process_id = start_evidence.get("process_id")
        if (
            not isinstance(service_process_id, int)
            or isinstance(service_process_id, bool)
            or service_process_id <= 0
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "activation service process id is invalid"
            )
        tunnel_before = qualify_running_secure_mcp_tunnel(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        hello = _wait_for_authenticated_hello(
            presence_path,
            instance_id=config.instance_id,
            boot_id=str(guest_before["health_boot_id"]),
            not_before_unix=started_at_unix,
            timeout_seconds=float(request.hello_timeout_seconds),
        )
        heartbeat = _wait_for_heartbeat_generation_stability(
            presence_path,
            hello,
            margin_seconds=float(request.heartbeat_margin_seconds),
        )
        guest_after_heartbeat = _observe_guest_agent(
            config,
            request.guest_credential,
        )
        if (
            guest_after_heartbeat["health_boot_id"] != hello.boot_id
            or guest_after_heartbeat["process_id"] != guest_before["process_id"]
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "HMSAgent process/boot changed before external challenge publication"
            )

        challenge = _new_challenge(request, instance_id=config.instance_id)
        write_json_create_only(
            request.challenge_path,
            _challenge_payload(challenge),
            max_bytes=_MAX_CHALLENGE_FILE_BYTES,
            label="external MCP read qualification challenge",
        )
        observer = _wait_for_external_observation(
            Path(config.runtime_root),
            challenge,
            timeout_seconds=float(request.external_timeout_seconds),
        )
        _require_observer_success(observer, challenge)

        after_result = _read_presence_read_only(
            presence_path,
            config.instance_id,
        )
        if (
            after_result is None
            or after_result.device_id != hello.device_id
            or after_result.boot_id != hello.boot_id
            or after_result.connection_epoch != hello.connection_epoch
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "Agent generation changed across external MCP read"
            )
        guest_after_result = _observe_guest_agent(
            config,
            request.guest_credential,
        )
        if (
            guest_after_result["health_boot_id"] != hello.boot_id
            or guest_after_result["process_id"] != guest_before["process_id"]
        ):
            raise BridgeExternalMcpCommandFlowQualificationError(
                "HMSAgent process/boot changed across external MCP read"
            )
        tunnel_after = qualify_running_secure_mcp_tunnel(
            service_sid=service_sid,
            service_process_id=service_process_id,
        )
        try:
            _require_same_tunnel_generation(tunnel_before, tunnel_after)
        except Exception as exc:
            raise BridgeExternalMcpCommandFlowQualificationError(
                "secure MCP tunnel generation changed across external MCP read"
            ) from exc
    except BaseException as exc:
        primary_error = exc
    finally:
        if started:
            try:
                stop_evidence = stop_hms_bridge_after_qualification(
                    config,
                    service_sid,
                )
            except BaseException as stop_exc:
                if primary_error is None:
                    primary_error = stop_exc
                else:
                    raise BridgeExternalMcpCommandFlowQualificationError(
                        "external MCP qualification failed and HMSBridge stop also failed"
                    ) from stop_exc

    if primary_error is not None:
        raise primary_error
    if any(
        value is None
        for value in (
            start_evidence,
            stop_evidence,
            tunnel_before,
            tunnel_after,
            observer,
            challenge,
            hello,
            heartbeat,
        )
    ):
        raise BridgeExternalMcpCommandFlowQualificationError(
            "external MCP qualification evidence is incomplete"
        )
    post = prove_hms_bridge_provisioning_identity()
    _require_stopped_manual(
        post,
        service_sid=service_sid,
        phase="external MCP qualification end",
    )

    return {
        "ready": True,
        "status": "EXTERNAL_PRINCIPAL_READ_WITH_STABLE_TUNNEL_QUALIFIED_STOPPED",
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": start_evidence["process_id"],
        "tunnel_process_id": tunnel_after["tunnel_process_id"],
        "tunnel_executable_sha256": tunnel_after["tunnel_executable_sha256"],
        "tunnel_readiness_body_class": tunnel_after["readiness_body_class"],
        "secure_mcp_tunnel_ready_during_external_flow": True,
        "tunnel_stable_across_external_flow": True,
        "agent_process_id": guest_before["process_id"],
        "agent_device_id": hello.device_id,
        "agent_boot_id": hello.boot_id,
        "agent_connection_epoch": hello.connection_epoch,
        "agent_generation_stable_across_external_flow": True,
        "challenge_id": challenge.challenge_id,
        "source_commit": challenge.source_commit,
        "instance_id": challenge.instance_id,
        "request_id": challenge.request_id,
        "path": challenge.path,
        "expected_content_sha256": challenge.expected_content_sha256,
        "workspace_content_size": observer["workspace_content_size"],
        "workspace_content_encoding": observer["workspace_content_encoding"],
        "principal_sha256": observer["principal_sha256"],
        "pair_id": observer["pair_id"],
        "session_id": observer["session_id"],
        "session_epoch": observer["session_epoch"],
        "agent_result_sha256": observer["agent_result_sha256"],
        "authenticated_principal_control_path_proven": True,
        "durable_external_principal_read_proven": True,
        "runner_invoked_mcp": False,
        "runner_enqueued_agent_command": False,
        "secure_tunnel_generation_proven": True,
        "listeners_absent_after_stop": True,
        "mcp_adapter_invocation_proven": False,
        "openai_control_plane_origin_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
