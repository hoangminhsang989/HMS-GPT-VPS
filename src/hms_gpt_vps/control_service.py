from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .control_actions import ControlActionRuntime
from .control_gateway import ControlGateway
from .control_request import ControlRequest


MAX_LOCAL_APPROVAL_AGE_SECONDS = 300


class LocalApprovalError(PermissionError):
    pass


@dataclass(frozen=True)
class TrustedLocalApproval:
    """Local-only approval bound to one exact destructive request.

    This object is intentionally absent from the network control-request schema.
    A trusted local UI/operator boundary may mint it after explicit approval; a
    remote ChatGPT/HMS request cannot set a boolean field to self-approve.
    """

    request_id: str
    instance_id: str
    action: str
    request_sha256: str
    approved_at: datetime

    def validate_for(self, request: ControlRequest, *, now: datetime | None = None) -> None:
        request.validate()
        checked_at = now or datetime.now(timezone.utc)
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise LocalApprovalError("approval verification time must be timezone-aware")
        approved_at = self.approved_at
        if approved_at.tzinfo is None or approved_at.utcoffset() is None:
            raise LocalApprovalError("approval timestamp must be timezone-aware")
        approved_at = approved_at.astimezone(timezone.utc)
        checked_at = checked_at.astimezone(timezone.utc)
        if checked_at < approved_at:
            raise LocalApprovalError("approval timestamp is in the future")
        if checked_at - approved_at > timedelta(seconds=MAX_LOCAL_APPROVAL_AGE_SECONDS):
            raise LocalApprovalError("local approval has expired")
        if self.request_id != request.request_id:
            raise LocalApprovalError("approval request_id mismatch")
        if self.instance_id != request.instance_id:
            raise LocalApprovalError("approval instance_id mismatch")
        if self.action != request.action:
            raise LocalApprovalError("approval action mismatch")
        if self.request_sha256.lower() != request.request_sha256().lower():
            raise LocalApprovalError("approval request hash mismatch")


def approve_control_request_locally(
    request: ControlRequest,
    *,
    now: datetime | None = None,
) -> TrustedLocalApproval:
    """Mint an approval only from a trusted local operator/UI boundary."""
    request.validate()
    approved_at = now or datetime.now(timezone.utc)
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        raise LocalApprovalError("approval timestamp must be timezone-aware")
    return TrustedLocalApproval(
        request_id=request.request_id,
        instance_id=request.instance_id,
        action=request.action,
        request_sha256=request.request_sha256(),
        approved_at=approved_at.astimezone(timezone.utc),
    )


class ControlService:
    """Execute one authenticated control request through the locked R001 policy path.

    Order is deliberate:
      1. authenticate session + scope;
      2. claim idempotency key durably;
      3. validate optional trusted local approval;
      4. execute the existing action runtime/policy/executor;
      5. persist the deterministic response for replay.

    If execution raises after the idempotency claim, the claim intentionally
    remains unresolved. A retry is blocked rather than risking a duplicated side
    effect after an ambiguous crash/failure window.
    """

    def __init__(self, gateway: ControlGateway, runtime: ControlActionRuntime) -> None:
        self.gateway = gateway
        self.runtime = runtime

    def handle(
        self,
        request: ControlRequest,
        session_token: str,
        *,
        local_approval: TrustedLocalApproval | None = None,
        now: datetime | None = None,
    ) -> dict:
        gate = self.gateway.begin(request, session_token, now=now)
        if not gate.should_execute:
            assert gate.replay_response is not None
            return dict(gate.replay_response)

        explicitly_approved = False
        if local_approval is not None:
            local_approval.validate_for(request, now=now)
            explicitly_approved = True

        response = self.runtime.execute(
            request,
            explicitly_approved=explicitly_approved,
        )
        return self.gateway.complete(gate, response, now=now)
