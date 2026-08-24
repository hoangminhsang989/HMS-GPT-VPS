from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import secrets

from . import __version__
from .agent_command_executor import AgentPolicyCommandExecutor
from .agent_connection_epoch_store import AgentConnectionEpochStore
from .agent_device_credential_store import (
    GuestAgentDeviceCredentialStore,
    guest_device_credential_path,
)
from .agent_health_server import (
    AgentHealthServer,
    AgentHealthServerConfig,
    AgentHealthState,
)
from .agent_https_client import AgentHttpsClient, AgentHttpsClientConfig
from .agent_runtime_runner import (
    AgentRuntimeRunner,
    AgentRuntimeRunnerConfig,
    ClientFactory,
    StopSignal,
)
from .agent_runtime_session import AgentRuntimeSessionConfig
from .agent_transport_protocol import AgentDeviceCredential
from .audit import AuditLog
from .control_actions import ControlActionRuntime
from .idempotency_store import IdempotencyStore
from .workspace import Workspace


DEFAULT_AGENT_WORKSPACE = Path(r"C:\HMS-Workspace")
DEFAULT_AGENT_STATE = Path(r"C:\ProgramData\HMS-GPT-VPS\State")
_AGENT_EPOCH_FILENAME = "agent-connection-epoch.sqlite3"
_AGENT_IDEMPOTENCY_FILENAME = "agent-idempotency.sqlite3"
_AGENT_AUDIT_FILENAME = "agent-audit.jsonl"


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _require_trusted_tool(
    raw: str,
    *,
    name: str,
    mutable_roots: tuple[Path, ...],
) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(f"{name} is required")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    if candidate.is_symlink():
        raise PermissionError(f"{name} must not be a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{name} does not exist: {candidate}") from exc
    if not resolved.is_file():
        raise FileNotFoundError(f"{name} is not a regular file: {resolved}")

    for mutable_root in mutable_roots:
        resolved_root = mutable_root.resolve(strict=True)
        if _is_within(resolved, resolved_root):
            raise PermissionError(
                f"{name} must not be located inside Agent-writable managed roots"
            )
    return str(resolved)


@dataclass(frozen=True)
class AgentGuestRuntimeConfig:
    instance_id: str
    project_id: str
    bridge_origin: str
    python_executable: str
    git_executable: str
    workspace_root: Path = DEFAULT_AGENT_WORKSPACE
    state_root: Path = DEFAULT_AGENT_STATE
    health_port: int = 8765
    agent_version: str = __version__

    def validate(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not self.project_id.strip():
            raise ValueError("project_id is required")
        if not isinstance(self.python_executable, str) or not self.python_executable.strip():
            raise ValueError("python_executable is required")
        if not Path(self.python_executable).is_absolute():
            raise ValueError("python_executable must be an absolute path")
        if not isinstance(self.git_executable, str) or not self.git_executable.strip():
            raise ValueError("git_executable is required")
        if not Path(self.git_executable).is_absolute():
            raise ValueError("git_executable must be an absolute path")
        if not self.agent_version.strip():
            raise ValueError("agent_version is required")
        AgentHttpsClientConfig(self.bridge_origin).validate()
        AgentHealthServerConfig(port=self.health_port).validate()

    def require_runtime_paths(self) -> None:
        self.validate()
        if not self.workspace_root.is_dir():
            raise FileNotFoundError(
                f"Agent workspace root does not exist: {self.workspace_root}"
            )
        if not self.state_root.is_dir():
            raise FileNotFoundError(
                f"Agent state root does not exist: {self.state_root}"
            )

        mutable_roots = (
            self.workspace_root.resolve(strict=True),
            self.state_root.resolve(strict=True),
        )
        _require_trusted_tool(
            self.python_executable,
            name="python_executable",
            mutable_roots=mutable_roots,
        )
        _require_trusted_tool(
            self.git_executable,
            name="git_executable",
            mutable_roots=mutable_roots,
        )


@dataclass(frozen=True)
class AgentRuntimeIdentity:
    service_identity: str
    privilege: str

    def validate(self) -> None:
        if self.service_identity.casefold() != r"NT SERVICE\HMSAgent".casefold():
            raise ValueError("runtime identity must be the HMSAgent service SID")
        if self.privilege != "non-admin":
            raise ValueError("runtime privilege must be non-admin")


class AgentGuestRuntime:
    """Compose the real guest Agent runtime from existing fail-closed pieces.

    This class owns lifecycle composition only. It does not implement Windows
    SCM integration or claim that the current process identity has been proven.
    The service host must supply a validated ``AgentRuntimeIdentity`` after its
    native identity checks pass.
    """

    def __init__(
        self,
        config: AgentGuestRuntimeConfig,
        credential: AgentDeviceCredential,
        identity: AgentRuntimeIdentity,
        *,
        boot_id: str | None = None,
        client_factory: ClientFactory | None = None,
        runner_config: AgentRuntimeRunnerConfig | None = None,
        session_config: AgentRuntimeSessionConfig | None = None,
    ) -> None:
        config.require_runtime_paths()
        credential.validate()
        identity.validate()
        if credential.instance_id != config.instance_id:
            raise PermissionError(
                "guest Agent credential belongs to another managed instance"
            )

        self.config = config
        self.credential = credential
        self.identity = identity
        self.boot_id = boot_id or secrets.token_urlsafe(16)

        workspace = Workspace(
            project_id=config.project_id,
            root=config.workspace_root,
        )
        action_runtime = ControlActionRuntime(
            instance_id=config.instance_id,
            workspace=workspace,
            audit_log=AuditLog(config.state_root / _AGENT_AUDIT_FILENAME),
            python_executable=_require_trusted_tool(
                config.python_executable,
                name="python_executable",
                mutable_roots=(
                    config.workspace_root.resolve(strict=True),
                    config.state_root.resolve(strict=True),
                ),
            ),
            git_executable=_require_trusted_tool(
                config.git_executable,
                name="git_executable",
                mutable_roots=(
                    config.workspace_root.resolve(strict=True),
                    config.state_root.resolve(strict=True),
                ),
            ),
        )
        executor = AgentPolicyCommandExecutor(action_runtime)

        idempotency = IdempotencyStore(
            config.state_root / _AGENT_IDEMPOTENCY_FILENAME
        )
        epoch_store = AgentConnectionEpochStore(
            config.state_root / _AGENT_EPOCH_FILENAME
        )

        https_config = AgentHttpsClientConfig(config.bridge_origin)

        def default_client_factory(
            creds: AgentDeviceCredential,
            runtime_boot_id: str,
            connection_epoch: int,
        ) -> AgentHttpsClient:
            return AgentHttpsClient(
                https_config,
                creds,
                boot_id=runtime_boot_id,
                connection_epoch=connection_epoch,
            )

        self.runner = AgentRuntimeRunner(
            credential,
            epoch_store,
            idempotency,
            executor,
            client_factory or default_client_factory,
            config=runner_config,
            session_config=session_config,
            boot_id=self.boot_id,
        )
        self.health = AgentHealthServer(
            AgentHealthState(
                instance_id=config.instance_id,
                agent_version=config.agent_version,
                workspace_root=str(config.workspace_root),
                boot_id=self.runner.boot_id,
                service_identity=identity.service_identity,
                privilege=identity.privilege,
            ),
            config=AgentHealthServerConfig(port=config.health_port),
        )

    @classmethod
    def from_guest_state(
        cls,
        config: AgentGuestRuntimeConfig,
        identity: AgentRuntimeIdentity,
        *,
        credential_store: GuestAgentDeviceCredentialStore | None = None,
        boot_id: str | None = None,
        client_factory: ClientFactory | None = None,
        runner_config: AgentRuntimeRunnerConfig | None = None,
        session_config: AgentRuntimeSessionConfig | None = None,
    ) -> "AgentGuestRuntime":
        config.require_runtime_paths()
        store = credential_store or GuestAgentDeviceCredentialStore(
            guest_device_credential_path(config.state_root)
        )
        credential = store.load(expected_instance_id=config.instance_id)
        return cls(
            config,
            credential,
            identity,
            boot_id=boot_id,
            client_factory=client_factory,
            runner_config=runner_config,
            session_config=session_config,
        )

    def run(self, stop: StopSignal) -> None:
        """Serve loopback health only while the outbound Agent runner is alive."""
        self.health.start()
        try:
            self.runner.run(stop)
        finally:
            self.health.shutdown()
