from __future__ import annotations

from dataclasses import dataclass

from .agent_runtime_session import AgentExecutionResponse
from .agent_transport_protocol import AgentCommandEnvelope
from .control_actions import (
    ControlActionPreconditionError,
    ControlActionRuntime,
)
from .control_request import CONTROL_REQUEST_SCHEMA_VERSION, ControlRequest
from .executor import ExecutionDenied
from .workspace import WorkspaceViolation


_AGENT_TRANSPORT_SESSION_ID = "agent-transport"


@dataclass(frozen=True)
class AgentPolicyCommandExecutor:
    """Adapt a verified Bridge command to the existing policy-gated runtime.

    The Agent transport has already authenticated the Bridge command with the
    device credential and verified its deadline before this adapter is called.
    This layer deliberately does not introduce a second executor or any shell
    surface: it converts the command into the existing five-action
    ``ControlActionRuntime``.

    ``approved_command_sha256`` is treated only as the Bridge's signed assertion
    that the exact command passed the trusted local approval boundary. The
    ControlActionRuntime still applies the destructive-action policy and the
    exact existing-content SHA-256 precondition for replace operations.
    """

    runtime: ControlActionRuntime

    def __call__(self, command: AgentCommandEnvelope) -> AgentExecutionResponse:
        command.validate()

        request = ControlRequest(
            schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
            request_id=command.request_id,
            instance_id=command.instance_id,
            session_id=_AGENT_TRANSPORT_SESSION_ID,
            action=command.action,
            params=dict(command.params),
        )

        try:
            response = self.runtime.execute(
                request,
                explicitly_approved=command.is_destructive_approved(),
            )
        except (ExecutionDenied, PermissionError):
            return AgentExecutionResponse(
                outcome="denied",
                response={"error": "command denied"},
            )
        except (
            ControlActionPreconditionError,
            FileNotFoundError,
            WorkspaceViolation,
            ValueError,
        ):
            return AgentExecutionResponse(
                outcome="failed",
                response={"error": "command precondition failed"},
            )

        outcome = "failed" if response.get("ok") is False else "ok"
        return AgentExecutionResponse(
            outcome=outcome,
            response=dict(response),
        )
