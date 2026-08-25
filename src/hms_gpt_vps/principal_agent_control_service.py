from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Callable, Mapping

from .agent_bridge_service import AgentBridgeService
from .agent_command_exact_status import get_exact_agent_command_status
from .agent_command_store import AgentCommandState, AgentCommandStatus
from .agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    AgentCommandResult,
)
from .control_gateway import ControlGate, ControlGateway
from .control_request import (
    CONTROL_REQUEST_SCHEMA_VERSION,
    ControlRequest,
    authorize_control_request,
)
from .principal_dispatch_intent import (
    PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION,
    PrincipalDispatchClaimState,
    PrincipalDispatchIntent,
    PrincipalDispatchIntentAmbiguousError,
    PrincipalDispatchIntentStore,
)
from .principal_pairing_service import (
    PrincipalPairingResult,
    PrincipalPairingService,
    PrincipalSessionBinding,
    TrustedIntegrationPrincipal,
)


PRINCIPAL_CONTROL_RECEIPT_SCHEMA_VERSION = 1
_RECEIPT_KIND = "agent_completed"
_HEX_LOWER = frozenset("0123456789abcdef")
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "instance_id",
        "request_id",
        "command_sha256",
        "result_sha256",
    }
)


class PrincipalAgentControlError(RuntimeError):
    pass


class PrincipalAgentControlUnavailableError(PrincipalAgentControlError):
    pass


class PrincipalAgentControlConflictError(PrincipalAgentControlError):
    pass


class PrincipalAgentControlAmbiguousError(PrincipalAgentControlError):
    pass


class PrincipalAgentControlApprovalRequiredError(PrincipalAgentControlError):
    pass


class PrincipalControlState(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class PrincipalControlStatus:
    instance_id: str
    request_id: str
    state: PrincipalControlState
    outcome: str | None = None
    response: dict[str, Any] | None = None
    completed_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "instance_id": self.instance_id,
            "request_id": self.request_id,
            "state": self.state.value,
        }
        if self.outcome is not None:
            payload["outcome"] = self.outcome
        if self.response is not None:
            payload["response"] = dict(self.response)
        if self.completed_at is not None:
            payload["completed_at"] = _iso(self.completed_at)
        return payload


def _aware_utc(value: datetime) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise PrincipalAgentControlError(
            "principal control clock must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware_utc(value).isoformat().replace("+00:00", "Z")


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PrincipalAgentControlError(
            "principal control authority is not JSON-safe"
        ) from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _canonical_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in _HEX_LOWER for char in value)
    ):
        raise PrincipalAgentControlConflictError(
            f"{name} is not canonical SHA-256"
        )
    return value


def _command_sha256(command: AgentCommandEnvelope) -> str:
    command.validate()
    return _sha256(command.to_dict())


def _result_sha256(result: AgentCommandResult) -> str:
    result.validate()
    return _sha256(result.to_dict())


def _completed_receipt(
    command: AgentCommandEnvelope,
    result: AgentCommandResult,
) -> dict[str, Any]:
    if (
        command.instance_id != result.instance_id
        or command.request_id != result.request_id
    ):
        raise PrincipalAgentControlConflictError(
            "Agent result identity differs from dispatched command"
        )
    return {
        "schema_version": PRINCIPAL_CONTROL_RECEIPT_SCHEMA_VERSION,
        "kind": _RECEIPT_KIND,
        "instance_id": command.instance_id,
        "request_id": command.request_id,
        "command_sha256": _command_sha256(command),
        "result_sha256": _result_sha256(result),
    }


def _verify_completed_receipt(
    receipt: Mapping[str, Any],
    command: AgentCommandEnvelope,
    result: AgentCommandResult,
) -> None:
    if not isinstance(receipt, Mapping) or frozenset(receipt.keys()) != _RECEIPT_FIELDS:
        raise PrincipalAgentControlConflictError(
            "cached principal control receipt fields do not match schema"
        )
    schema = receipt["schema_version"]
    if (
        isinstance(schema, bool)
        or not isinstance(schema, int)
        or schema != PRINCIPAL_CONTROL_RECEIPT_SCHEMA_VERSION
    ):
        raise PrincipalAgentControlConflictError(
            "cached principal control receipt schema is invalid"
        )
    if receipt["kind"] != _RECEIPT_KIND:
        raise PrincipalAgentControlConflictError(
            "cached principal control receipt kind is invalid"
        )
    if receipt["instance_id"] != command.instance_id:
        raise PrincipalAgentControlConflictError(
            "cached receipt instance_id mismatch"
        )
    if receipt["request_id"] != command.request_id:
        raise PrincipalAgentControlConflictError(
            "cached receipt request_id mismatch"
        )
    command_digest = _canonical_sha256(
        receipt["command_sha256"],
        "cached command_sha256",
    )
    result_digest = _canonical_sha256(
        receipt["result_sha256"],
        "cached result_sha256",
    )
    if command_digest != _command_sha256(command):
        raise PrincipalAgentControlConflictError(
            "cached receipt command digest mismatch"
        )
    if result_digest != _result_sha256(result):
        raise PrincipalAgentControlConflictError(
            "cached receipt result digest mismatch"
        )


class PrincipalAgentControlService:
    """Principal-bound Bridge façade that dispatches only to the managed Agent.

    Raw pairing/session bearer credentials remain inside PrincipalPairingService.
    This service never executes ControlActionRuntime on the Bridge host. It first
    authorizes the exact principal-bound session, then atomically binds the
    idempotency key to one exact Agent dispatch before the command can become
    pollable by the managed guest.
    """

    def __init__(
        self,
        principal_pairing: PrincipalPairingService,
        gateway: ControlGateway,
        agent_bridge: AgentBridgeService,
        intent_store: PrincipalDispatchIntentStore,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(principal_pairing, PrincipalPairingService):
            raise TypeError(
                "principal_pairing must be a PrincipalPairingService"
            )
        if not isinstance(gateway, ControlGateway):
            raise TypeError("gateway must be a ControlGateway")
        if not isinstance(agent_bridge, AgentBridgeService):
            raise TypeError("agent_bridge must be an AgentBridgeService")
        if not isinstance(intent_store, PrincipalDispatchIntentStore):
            raise TypeError(
                "intent_store must be a PrincipalDispatchIntentStore"
            )
        if gateway.session_store is not principal_pairing.exchange.session_store:
            raise PrincipalAgentControlError(
                "principal control requires gateway and pairing to share exact ControlSessionStore"
            )
        if intent_store.idempotency_store is not gateway.idempotency_store:
            raise PrincipalAgentControlError(
                "principal control requires dispatch and gateway to share exact IdempotencyStore"
            )
        self.principal_pairing = principal_pairing
        self.gateway = gateway
        self.agent_bridge = agent_bridge
        self.intent_store = intent_store
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def _now(self) -> datetime:
        return _aware_utc(self._clock())

    def pair_vps(
        self,
        principal: TrustedIntegrationPrincipal,
        pairing_link: str,
    ) -> PrincipalPairingResult:
        return self.principal_pairing.pair(principal, pairing_link)

    def _require_fresh_pairing(
        self,
        binding: PrincipalSessionBinding,
    ) -> None:
        observation = self.principal_pairing.readiness.observe()
        if (
            observation.pairing_ready is not True
            or observation.paired is not True
            or observation.pair_id != binding.pair_id
        ):
            raise PrincipalAgentControlUnavailableError(
                "managed Agent pairing is not currently fresh"
            )

    @staticmethod
    def _status_from_result(
        result: AgentCommandResult,
    ) -> PrincipalControlStatus:
        result.validate()
        return PrincipalControlStatus(
            instance_id=result.instance_id,
            request_id=result.request_id,
            state=PrincipalControlState.COMPLETED,
            outcome=result.outcome,
            response=dict(result.response),
            completed_at=result.completed_at,
        )

    def _replay_completed(
        self,
        command: AgentCommandEnvelope,
        receipt: Mapping[str, Any],
    ) -> PrincipalControlStatus:
        status = get_exact_agent_command_status(
            self.agent_bridge.commands,
            command,
        )
        if (
            status is None
            or status.state is not AgentCommandState.COMPLETED
            or status.result is None
        ):
            raise PrincipalAgentControlConflictError(
                "completed idempotency receipt lacks exact completed Agent command authority"
            )
        _verify_completed_receipt(receipt, command, status.result)
        return self._status_from_result(status.result)

    @staticmethod
    def _reject_unapproved_destructive_request(request: ControlRequest) -> None:
        if request.action != "workspace.write":
            return
        mode = request.params.get("mode", "create")
        if mode == "replace":
            raise PrincipalAgentControlApprovalRequiredError(
                "workspace.write replace requires a separate explicit approval flow"
            )

    def _gate(
        self,
        request: ControlRequest,
        *,
        session_epoch: int,
    ) -> ControlGate:
        return ControlGate(
            request_id=request.request_id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            session_epoch=session_epoch,
            action=request.action,
            request_sha256=request.request_sha256(),
            replay_response=None,
        )

    def _audit_dispatch_claim(
        self,
        request: ControlRequest,
        *,
        request_sha256: str,
        session_epoch: int,
        state: PrincipalDispatchClaimState,
    ) -> None:
        if state is PrincipalDispatchClaimState.NEW:
            outcome = "authorized"
        elif state is PrincipalDispatchClaimState.RESUME:
            outcome = "idempotency_resume"
        else:
            outcome = "replay"
        self.gateway._audit(
            request,
            outcome,
            request_sha256=request_sha256,
            session_epoch=session_epoch,
        )

    def submit(
        self,
        principal: TrustedIntegrationPrincipal,
        *,
        instance_id: str,
        request_id: str,
        action: str,
        params: Mapping[str, Any],
    ) -> PrincipalControlStatus:
        now = self._now()
        binding = self.principal_pairing.load_active_binding(
            principal,
            instance_id,
        )
        request = ControlRequest(
            schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
            request_id=request_id,
            instance_id=instance_id,
            session_id=binding.session_id,
            action=action,
            params=dict(params) if isinstance(params, Mapping) else params,
        )
        request.validate()
        self._reject_unapproved_destructive_request(request)
        request_sha256 = request.request_sha256()

        # Authorization precedes any dispatch/idempotency mutation and keeps the
        # same denial-audit semantics as ControlGateway.begin().
        try:
            session = authorize_control_request(
                request,
                binding.session_token,
                self.gateway.session_store,
                now=now,
            )
        except Exception as exc:
            self.gateway._audit(
                request,
                "denied",
                request_sha256=request_sha256,
                error=type(exc).__name__,
            )
            raise
        if session.epoch != binding.epoch:
            raise PrincipalAgentControlConflictError(
                "principal binding epoch differs from authorized session"
            )
        self._require_fresh_pairing(binding)

        command = AgentCommandEnvelope(
            schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
            request_id=request.request_id,
            instance_id=request.instance_id,
            action=request.action,
            params=dict(request.params),
            deadline_at=binding.expires_at,
            approved_command_sha256=None,
        )
        command.validate()
        intent = PrincipalDispatchIntent(
            schema_version=PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION,
            principal_sha256=binding.principal_sha256,
            pair_id=binding.pair_id,
            session_id=binding.session_id,
            session_epoch=binding.epoch,
            instance_id=binding.instance_id,
            request_id=request.request_id,
            request_sha256=request_sha256,
            command_sha256=_command_sha256(command),
            expires_at=binding.expires_at,
        )
        try:
            claim = self.intent_store.begin(intent, now=now)
        except PrincipalDispatchIntentAmbiguousError as exc:
            self.gateway._audit(
                request,
                "idempotency_blocked",
                request_sha256=request_sha256,
                session_epoch=session.epoch,
                error=type(exc).__name__,
            )
            raise PrincipalAgentControlAmbiguousError(
                "idempotency claim is not owned by Agent dispatch"
            ) from exc

        self._audit_dispatch_claim(
            request,
            request_sha256=request_sha256,
            session_epoch=session.epoch,
            state=claim.state,
        )
        gate = self._gate(request, session_epoch=session.epoch)

        if claim.state is PrincipalDispatchClaimState.REPLAY:
            assert claim.replay_response is not None
            return self._replay_completed(command, claim.replay_response)

        # Re-observe immediately before making the command pollable. If this
        # fails after the atomic NEW claim, a later RESUME can safely continue.
        self._require_fresh_pairing(binding)
        status: AgentCommandStatus | None = get_exact_agent_command_status(
            self.agent_bridge.commands,
            command,
        )
        if status is None:
            status = self.agent_bridge.enqueue_command(command, now=now)

        if status.state is AgentCommandState.PENDING:
            return PrincipalControlStatus(
                instance_id=command.instance_id,
                request_id=command.request_id,
                state=PrincipalControlState.PENDING,
            )
        if status.state is AgentCommandState.COMPLETED:
            if status.result is None:
                raise PrincipalAgentControlConflictError(
                    "completed Agent command has no durable result"
                )
            receipt = _completed_receipt(command, status.result)
            self.gateway.complete(gate, receipt, now=now)
            return self._status_from_result(status.result)
        if status.state is AgentCommandState.EXPIRED:
            return PrincipalControlStatus(
                instance_id=command.instance_id,
                request_id=command.request_id,
                state=PrincipalControlState.AMBIGUOUS,
            )
        raise PrincipalAgentControlConflictError(
            f"unsupported Agent command state: {status.state.value}"
        )

    def write_file(
        self,
        principal: TrustedIntegrationPrincipal,
        *,
        instance_id: str,
        request_id: str,
        path: str,
        content: str,
    ) -> PrincipalControlStatus:
        return self.submit(
            principal,
            instance_id=instance_id,
            request_id=request_id,
            action="workspace.write",
            params={
                "path": path,
                "content": content,
                "mode": "create",
            },
        )

    def read_file(
        self,
        principal: TrustedIntegrationPrincipal,
        *,
        instance_id: str,
        request_id: str,
        path: str,
    ) -> PrincipalControlStatus:
        return self.submit(
            principal,
            instance_id=instance_id,
            request_id=request_id,
            action="workspace.read",
            params={"path": path},
        )
