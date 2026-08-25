from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier

from .agent_bridge_service import (
    AgentBridgeService,
    CommandCredentialResolver,
    RequestCredentialResolver,
)
from .agent_command_store import AgentCommandStore
from .agent_connection_registry import AgentConnectionRegistry
from .control_gateway import ControlGateway
from .control_session_store import ControlSessionStore
from .idempotency_store import IdempotencyStore
from .mcp_bridge_server import (
    HmsMcpBridgeConfig,
    build_hms_mcp_server,
    run_loopback_mcp_server,
)
from .pairing import DEFAULT_PAIR_TTL_SECONDS
from .pairing_exchange import PairingExchangeKey, PairingSessionExchange
from .pairing_link_lease import create_dpapi_pairing_link_lease_store
from .pairing_readiness_runtime import (
    DEFAULT_PAIRING_PRESENCE_MAX_AGE_SECONDS,
    PairingReadinessConfig,
    PairingReadinessRuntime,
)
from .pairing_store import PairingStore
from .principal_agent_control_service import PrincipalAgentControlService
from .principal_binding_registry_authority import (
    PinnedDpapiPrincipalBindingRegistry,
)
from .principal_dispatch_intent import PrincipalDispatchIntentStore
from .principal_pairing_service import PrincipalPairingService
from .provision_state import ProvisionStateStore
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
    require_existing_directory,
)


class BridgeProductionAssemblyError(RuntimeError):
    pass


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _require_identifier(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 128
    ):
        raise BridgeProductionAssemblyError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise BridgeProductionAssemblyError(
            f"{name} contains unsupported characters"
        )
    return value


def _require_fixed_child(root: Path, name: str) -> Path:
    if name not in {"db", "secrets", "locks"}:
        raise BridgeProductionAssemblyError(
            "unsupported Bridge runtime child directory"
        )
    before = require_existing_directory(
        root,
        label="Bridge production runtime root",
    ).stat()
    child = require_existing_directory(
        root / name,
        label=f"Bridge runtime {name} directory",
    )
    after = require_existing_directory(
        root,
        label="Bridge production runtime root",
    ).stat()
    if not _same_file_identity(before, after):
        raise BridgeProductionAssemblyError(
            "Bridge production runtime root identity changed"
        )
    return child


def _require_principal_binding_root(secrets_dir: Path) -> Path:
    before = require_existing_directory(
        secrets_dir,
        label="Bridge secrets directory",
    ).stat()
    child = require_existing_directory(
        secrets_dir / "principal-bindings",
        label="Bridge principal-binding directory",
    )
    after = require_existing_directory(
        secrets_dir,
        label="Bridge secrets directory",
    ).stat()
    if not _same_file_identity(before, after):
        raise BridgeProductionAssemblyError(
            "Bridge secrets directory identity changed"
        )
    return child


@dataclass(frozen=True)
class BridgeRuntimeLayout:
    root: Path
    db_dir: Path
    secrets_dir: Path
    locks_dir: Path
    principal_bindings_dir: Path
    auth_db_path: Path
    presence_db_path: Path
    command_db_path: Path
    idempotency_db_path: Path
    pairing_lease_path: Path
    pairing_issue_lock_path: Path
    principal_pairing_lock_path: Path

    @classmethod
    def prepare(cls, root: Path) -> "BridgeRuntimeLayout":
        authority = lexical_absolute(root)
        if path_chain_has_redirect(authority):
            raise BridgeProductionAssemblyError(
                "Bridge production runtime root traverses a link or reparse point"
            )
        authority = require_existing_directory(
            authority,
            label="Bridge production runtime root",
        )
        root_identity = authority.stat()
        db_dir = _require_fixed_child(authority, "db")
        secrets_dir = _require_fixed_child(authority, "secrets")
        locks_dir = _require_fixed_child(authority, "locks")
        principal_bindings_dir = _require_principal_binding_root(secrets_dir)
        final_root = require_existing_directory(
            authority,
            label="Bridge production runtime root",
        ).stat()
        if not _same_file_identity(root_identity, final_root):
            raise BridgeProductionAssemblyError(
                "Bridge production runtime root identity changed during layout preparation"
            )
        return cls(
            root=authority,
            db_dir=db_dir,
            secrets_dir=secrets_dir,
            locks_dir=locks_dir,
            principal_bindings_dir=principal_bindings_dir,
            auth_db_path=db_dir / "pairing-control.sqlite3",
            presence_db_path=db_dir / "agent-presence.sqlite3",
            command_db_path=db_dir / "agent-commands.sqlite3",
            idempotency_db_path=db_dir / "control-idempotency.sqlite3",
            pairing_lease_path=secrets_dir / "pairing-link.dpapi",
            pairing_issue_lock_path=locks_dir / "pairing-issuance.lock",
            principal_pairing_lock_path=locks_dir / "principal-pairing.lock",
        )


@dataclass(frozen=True)
class BridgeProductionConfig:
    runtime_root: Path
    provision_state_path: Path
    instance_id: str
    bridge_base_url: str
    mcp: HmsMcpBridgeConfig
    presence_max_age_seconds: int = DEFAULT_PAIRING_PRESENCE_MAX_AGE_SECONDS
    pair_ttl_seconds: int = DEFAULT_PAIR_TTL_SECONDS

    def validate(self) -> None:
        _require_identifier(self.instance_id, "instance_id")
        if not isinstance(self.runtime_root, Path):
            raise BridgeProductionAssemblyError(
                "runtime_root must be a pathlib.Path"
            )
        if not isinstance(self.provision_state_path, Path):
            raise BridgeProductionAssemblyError(
                "provision_state_path must be a pathlib.Path"
            )
        state_path = lexical_absolute(self.provision_state_path)
        if path_chain_has_redirect(state_path):
            raise BridgeProductionAssemblyError(
                "provision_state_path traverses a link or reparse point"
            )
        if not state_path.parent.exists() or not state_path.parent.is_dir():
            raise BridgeProductionAssemblyError(
                "provision_state_path parent must already exist"
            )
        PairingReadinessConfig(
            instance_id=self.instance_id,
            bridge_base_url=self.bridge_base_url,
            presence_max_age_seconds=self.presence_max_age_seconds,
            pair_ttl_seconds=self.pair_ttl_seconds,
        ).validate()
        self.mcp.validate()


@dataclass(frozen=True)
class BridgeProductionDependencies:
    pairing_exchange_key: PairingExchangeKey
    request_credential_resolver: RequestCredentialResolver
    command_credential_resolver: CommandCredentialResolver
    oauth_token_verifier: TokenVerifier

    def validate(self) -> None:
        if not isinstance(self.pairing_exchange_key, PairingExchangeKey):
            raise TypeError(
                "pairing_exchange_key must be a PairingExchangeKey"
            )
        if not callable(self.request_credential_resolver):
            raise TypeError(
                "request_credential_resolver must be callable"
            )
        if not callable(self.command_credential_resolver):
            raise TypeError(
                "command_credential_resolver must be callable"
            )
        if not callable(
            getattr(self.oauth_token_verifier, "verify_token", None)
        ):
            raise TypeError(
                "oauth_token_verifier must implement verify_token"
            )


@dataclass(frozen=True)
class BridgeProductionAssembly:
    config: BridgeProductionConfig
    layout: BridgeRuntimeLayout
    provision_store: ProvisionStateStore
    pairing_store: PairingStore
    session_store: ControlSessionStore
    pairing_exchange: PairingSessionExchange
    presence_registry: AgentConnectionRegistry
    command_store: AgentCommandStore
    agent_bridge: AgentBridgeService
    readiness: PairingReadinessRuntime
    principal_pairing: PrincipalPairingService
    idempotency_store: IdempotencyStore
    gateway: ControlGateway
    dispatch_intent_store: PrincipalDispatchIntentStore
    principal_control: PrincipalAgentControlService
    mcp_server: MCPServer

    def run_mcp(self) -> None:
        run_loopback_mcp_server(self.mcp_server, self.config.mcp)


def assemble_production_bridge(
    config: BridgeProductionConfig,
    dependencies: BridgeProductionDependencies,
) -> BridgeProductionAssembly:
    if not isinstance(config, BridgeProductionConfig):
        raise TypeError("config must be a BridgeProductionConfig")
    if not isinstance(dependencies, BridgeProductionDependencies):
        raise TypeError(
            "dependencies must be BridgeProductionDependencies"
        )
    config.validate()
    dependencies.validate()

    layout = BridgeRuntimeLayout.prepare(config.runtime_root)
    provision_store = ProvisionStateStore(
        lexical_absolute(config.provision_state_path)
    )

    pairing_store = PairingStore(layout.auth_db_path)
    session_store = ControlSessionStore(layout.auth_db_path)
    pairing_exchange = PairingSessionExchange(
        pairing_store,
        session_store,
        dependencies.pairing_exchange_key,
    )

    presence_registry = AgentConnectionRegistry(
        layout.presence_db_path
    )
    command_store = AgentCommandStore(layout.command_db_path)
    agent_bridge = AgentBridgeService(
        presence_registry,
        command_store,
        dependencies.request_credential_resolver,
        dependencies.command_credential_resolver,
    )

    readiness = PairingReadinessRuntime(
        PairingReadinessConfig(
            instance_id=config.instance_id,
            bridge_base_url=config.bridge_base_url,
            presence_max_age_seconds=config.presence_max_age_seconds,
            pair_ttl_seconds=config.pair_ttl_seconds,
        ),
        provision_store,
        presence_registry,
        pairing_store,
        create_dpapi_pairing_link_lease_store(
            layout.pairing_lease_path
        ),
        layout.pairing_issue_lock_path,
    )

    principal_pairing = PrincipalPairingService(
        readiness,
        pairing_exchange,
        PinnedDpapiPrincipalBindingRegistry(
            layout.principal_bindings_dir
        ),
        layout.principal_pairing_lock_path,
    )

    idempotency_store = IdempotencyStore(
        layout.idempotency_db_path
    )
    gateway = ControlGateway(
        session_store,
        idempotency_store,
    )
    dispatch_intent_store = PrincipalDispatchIntentStore(
        idempotency_store
    )
    principal_control = PrincipalAgentControlService(
        principal_pairing,
        gateway,
        agent_bridge,
        dispatch_intent_store,
    )
    mcp_server = build_hms_mcp_server(
        principal_control,
        dependencies.oauth_token_verifier,
        config.mcp,
    )

    return BridgeProductionAssembly(
        config=config,
        layout=layout,
        provision_store=provision_store,
        pairing_store=pairing_store,
        session_store=session_store,
        pairing_exchange=pairing_exchange,
        presence_registry=presence_registry,
        command_store=command_store,
        agent_bridge=agent_bridge,
        readiness=readiness,
        principal_pairing=principal_pairing,
        idempotency_store=idempotency_store,
        gateway=gateway,
        dispatch_intent_store=dispatch_intent_store,
        principal_control=principal_control,
        mcp_server=mcp_server,
    )
