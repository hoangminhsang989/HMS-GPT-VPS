from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .audit import AuditLog
from .control_request import ControlRequest, authorize_control_request
from .control_session import ControlSessionRecord
from .control_session_store import ControlSessionStore
from .idempotency_store import IdempotencyClaim, IdempotencyStore


@dataclass(frozen=True)
class ControlGate:
    request_id: str
    instance_id: str
    session_id: str
    session_epoch: int
    action: str
    request_sha256: str
    replay_response: dict[str, Any] | None = None

    @property
    def should_execute(self) -> bool:
        return self.replay_response is None


class ControlGateway:
    """Authentication + scope + idempotency front door for Agent actions.

    It deliberately does not execute workspace/process operations itself. The
    existing R001 policy/executor remains the downstream enforcement layer.
    Raw session tokens and request parameters are never written to the gateway
    audit event or idempotency database.
    """

    def __init__(
        self,
        session_store: ControlSessionStore,
        idempotency_store: IdempotencyStore,
        *,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.session_store = session_store
        self.idempotency_store = idempotency_store
        self.audit_log = audit_log

    def _audit(
        self,
        request: ControlRequest,
        outcome: str,
        *,
        request_sha256: str | None = None,
        session_epoch: int | None = None,
        error: str | None = None,
    ) -> None:
        if self.audit_log is None:
            return
        detail: dict[str, Any] = {
            "request_id": request.request_id,
            "session_id": request.session_id,
        }
        if request_sha256 is not None:
            detail["request_sha256"] = request_sha256
        if session_epoch is not None:
            detail["session_epoch"] = session_epoch
        if error is not None:
            detail["error"] = error
        self.audit_log.append(
            action=f"control.{request.action}",
            project_id=request.instance_id,
            outcome=outcome,
            **detail,
        )

    def begin(
        self,
        request: ControlRequest,
        session_token: str,
        *,
        now: datetime | None = None,
    ) -> ControlGate:
        request.validate()
        request_sha256 = request.request_sha256()
        try:
            session: ControlSessionRecord = authorize_control_request(
                request,
                session_token,
                self.session_store,
                now=now,
            )
        except Exception as exc:
            self._audit(
                request,
                "denied",
                request_sha256=request_sha256,
                error=type(exc).__name__,
            )
            raise

        try:
            claim: IdempotencyClaim = self.idempotency_store.claim(
                request.session_id,
                request.request_id,
                request_sha256,
                now=now,
            )
        except Exception as exc:
            self._audit(
                request,
                "idempotency_blocked",
                request_sha256=request_sha256,
                session_epoch=session.epoch,
                error=type(exc).__name__,
            )
            raise

        outcome = "replay" if not claim.is_new else "authorized"
        self._audit(
            request,
            outcome,
            request_sha256=request_sha256,
            session_epoch=session.epoch,
        )
        return ControlGate(
            request_id=request.request_id,
            instance_id=request.instance_id,
            session_id=request.session_id,
            session_epoch=session.epoch,
            action=request.action,
            request_sha256=request_sha256,
            replay_response=claim.replay_response,
        )

    def complete(
        self,
        gate: ControlGate,
        response: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if not gate.should_execute:
            raise ValueError("replayed control request is already completed")
        completed = self.idempotency_store.complete(
            gate.session_id,
            gate.request_id,
            gate.request_sha256,
            response,
            now=now,
        )
        if self.audit_log is not None:
            self.audit_log.append(
                action=f"control.{gate.action}",
                project_id=gate.instance_id,
                outcome="completed",
                request_id=gate.request_id,
                session_id=gate.session_id,
                request_sha256=gate.request_sha256,
                session_epoch=gate.session_epoch,
            )
        return completed
