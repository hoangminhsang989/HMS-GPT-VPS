from __future__ import annotations

from dataclasses import dataclass
from threading import Event, Thread
import time
from typing import Any, Callable, Protocol

from mcp.server.auth.provider import TokenVerifier

from .agent_bridge_production_tls import (
    AgentBridgeProductionTlsConfig,
    AgentBridgeProductionTlsRuntime,
    start_agent_bridge_production_tls,
)
from .bridge_production_assembly import (
    BridgeProductionAssembly,
    BridgeProductionConfig,
    BridgeProductionDependencies,
    assemble_production_bridge,
)
from .bridge_service_dependency_loader import (
    BridgeServiceSecretDependencies,
    load_bridge_service_secret_dependencies,
)
from .bridge_service_identity import (
    prove_hms_bridge_runtime_identity,
    require_hms_bridge_service_sid,
)
from .bridge_service_secret_storage import BridgeServiceSecretStorageConfig


_LOOPBACK_HOST = "127.0.0.1"
_MCP_PATH = "/mcp"
_DEFAULT_STARTUP_TIMEOUT_SECONDS = 30
_DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 30


class BridgeProductionServiceRuntimeError(RuntimeError):
    pass


class McpAsgiServer(Protocol):
    started: bool
    should_exit: bool
    force_exit: bool

    def run(self) -> None: ...


McpAsgiServerFactory = Callable[[Any, str, int], McpAsgiServer]


@dataclass(frozen=True)
class BridgeProductionServiceRuntimeConfig:
    expected_service_sid: str
    secret_storage: BridgeServiceSecretStorageConfig
    production: BridgeProductionConfig
    tls: AgentBridgeProductionTlsConfig
    startup_timeout_seconds: int = _DEFAULT_STARTUP_TIMEOUT_SECONDS
    shutdown_timeout_seconds: int = _DEFAULT_SHUTDOWN_TIMEOUT_SECONDS

    def validate(self) -> None:
        expected_sid = require_hms_bridge_service_sid(self.expected_service_sid)
        if not isinstance(self.secret_storage, BridgeServiceSecretStorageConfig):
            raise TypeError("secret_storage must be a BridgeServiceSecretStorageConfig")
        if not isinstance(self.production, BridgeProductionConfig):
            raise TypeError("production must be a BridgeProductionConfig")
        if not isinstance(self.tls, AgentBridgeProductionTlsConfig):
            raise TypeError("tls must be an AgentBridgeProductionTlsConfig")
        self.secret_storage.validate()
        self.production.validate()
        self.tls.validate()

        if self.secret_storage.bridge_reader_sid != expected_sid:
            raise BridgeProductionServiceRuntimeError(
                "service secret reader SID differs from HMSBridge service authority"
            )
        if self.tls.storage.bridge_reader_sid != expected_sid:
            raise BridgeProductionServiceRuntimeError(
                "TLS private-key reader SID differs from HMSBridge service authority"
            )

        runtime_secrets = self.production.runtime_root.expanduser().absolute() / "secrets"
        secret_parent = self.secret_storage.root.expanduser().absolute().parent
        if secret_parent != runtime_secrets:
            raise BridgeProductionServiceRuntimeError(
                "service secret root is outside the production Bridge secrets directory"
            )

        for value, name in (
            (self.startup_timeout_seconds, "startup_timeout_seconds"),
            (self.shutdown_timeout_seconds, "shutdown_timeout_seconds"),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= 300
            ):
                raise BridgeProductionServiceRuntimeError(
                    f"{name} must be an integer from 1 through 300"
                )


def _default_mcp_asgi_server_factory(
    mcp_server: Any,
    host: str,
    port: int,
) -> McpAsgiServer:
    if host != _LOOPBACK_HOST:
        raise BridgeProductionServiceRuntimeError(
            "production MCP ASGI server must bind exact loopback"
        )
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - product dependency gate
        raise BridgeProductionServiceRuntimeError(
            "uvicorn is required by the Bridge production MCP runtime"
        ) from exc

    app = mcp_server.streamable_http_app(
        host=_LOOPBACK_HOST,
        streamable_http_path=_MCP_PATH,
        stateless_http=True,
        json_response=True,
    )
    server = uvicorn.Server(
        uvicorn.Config(
            app=app,
            host=_LOOPBACK_HOST,
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
    )
    return server


@dataclass
class BridgeProductionServiceRuntime:
    config: BridgeProductionServiceRuntimeConfig
    assembly: BridgeProductionAssembly
    mcp_server_factory: McpAsgiServerFactory = _default_mcp_asgi_server_factory

    def __post_init__(self) -> None:
        if not isinstance(self.config, BridgeProductionServiceRuntimeConfig):
            raise TypeError("config must be a BridgeProductionServiceRuntimeConfig")
        if not isinstance(self.assembly, BridgeProductionAssembly):
            raise TypeError("assembly must be a BridgeProductionAssembly")
        if not callable(self.mcp_server_factory):
            raise TypeError("mcp_server_factory must be callable")
        self.config.validate()
        if self.assembly.config != self.config.production:
            raise BridgeProductionServiceRuntimeError(
                "Bridge assembly config differs from service runtime authority"
            )

    def _stop_mcp_server(
        self,
        server: McpAsgiServer,
        thread: Thread,
    ) -> None:
        server.should_exit = True
        thread.join(timeout=float(self.config.shutdown_timeout_seconds))
        if thread.is_alive():
            server.force_exit = True
            thread.join(timeout=float(self.config.shutdown_timeout_seconds))
        if thread.is_alive():
            raise BridgeProductionServiceRuntimeError(
                "MCP ASGI server thread did not stop within bounded shutdown"
            )

    def run(self, stop: Event) -> None:
        if not isinstance(stop, Event):
            raise TypeError("stop must be a threading.Event")
        self.config.validate()
        if stop.is_set():
            return

        # Re-prove the effective token at the last possible boundary before any
        # listener starts. The service host and dependency loader also prove it.
        prove_hms_bridge_runtime_identity(self.config.expected_service_sid)

        tls_runtime: AgentBridgeProductionTlsRuntime | None = None
        mcp_thread: Thread | None = None
        mcp_server: McpAsgiServer | None = None
        mcp_error: list[BaseException] = []

        try:
            tls_runtime = start_agent_bridge_production_tls(
                self.assembly.agent_http,
                self.config.tls,
            )
            expected_tls = (
                self.config.tls.firewall.network.gateway,
                self.config.tls.firewall.port,
            )
            if tls_runtime.bound_address != expected_tls:
                raise BridgeProductionServiceRuntimeError(
                    "production Agent TLS runtime returned the wrong bind authority"
                )

            mcp_server = self.mcp_server_factory(
                self.assembly.mcp_server,
                _LOOPBACK_HOST,
                self.config.production.mcp.port,
            )
            for attr in ("run", "started", "should_exit", "force_exit"):
                if not hasattr(mcp_server, attr):
                    raise BridgeProductionServiceRuntimeError(
                        "MCP ASGI server factory returned an invalid server"
                    )

            def run_mcp() -> None:
                try:
                    mcp_server.run()
                except BaseException as exc:
                    mcp_error.append(exc)

            mcp_thread = Thread(
                target=run_mcp,
                name="HMSBridgeMCP",
                daemon=False,
            )
            mcp_thread.start()

            deadline = time.monotonic() + self.config.startup_timeout_seconds
            while not bool(mcp_server.started):
                if mcp_error:
                    raise BridgeProductionServiceRuntimeError(
                        "MCP ASGI server failed during startup"
                    ) from mcp_error[0]
                if not mcp_thread.is_alive():
                    raise BridgeProductionServiceRuntimeError(
                        "MCP ASGI server exited before startup completed"
                    )
                if stop.is_set():
                    self._stop_mcp_server(mcp_server, mcp_thread)
                    return
                if time.monotonic() >= deadline:
                    raise BridgeProductionServiceRuntimeError(
                        "MCP ASGI server did not report startup within bounded time"
                    )
                stop.wait(0.05)

            while not stop.wait(0.20):
                if mcp_error:
                    raise BridgeProductionServiceRuntimeError(
                        "MCP ASGI server failed while service was running"
                    ) from mcp_error[0]
                if not mcp_thread.is_alive():
                    raise BridgeProductionServiceRuntimeError(
                        "MCP ASGI server exited before SCM stop"
                    )

            self._stop_mcp_server(mcp_server, mcp_thread)
            if mcp_error:
                raise BridgeProductionServiceRuntimeError(
                    "MCP ASGI server raised during shutdown"
                ) from mcp_error[0]
        finally:
            if mcp_server is not None and mcp_thread is not None and mcp_thread.is_alive():
                try:
                    self._stop_mcp_server(mcp_server, mcp_thread)
                except Exception:
                    if tls_runtime is not None:
                        try:
                            tls_runtime.shutdown()
                        finally:
                            tls_runtime = None
                    raise
            if tls_runtime is not None:
                tls_runtime.shutdown()


def build_bridge_production_service_runtime(
    config: BridgeProductionServiceRuntimeConfig,
    oauth_token_verifier: TokenVerifier,
    *,
    mcp_server_factory: McpAsgiServerFactory | None = None,
) -> BridgeProductionServiceRuntime:
    if not isinstance(config, BridgeProductionServiceRuntimeConfig):
        raise TypeError("config must be a BridgeProductionServiceRuntimeConfig")
    if not callable(getattr(oauth_token_verifier, "verify_token", None)):
        raise TypeError("oauth_token_verifier must implement verify_token")
    config.validate()

    # First gate: no secret loader or assembly construction under a privileged or
    # otherwise unexpected host token.
    prove_hms_bridge_runtime_identity(config.expected_service_sid)

    secret_dependencies: BridgeServiceSecretDependencies = (
        load_bridge_service_secret_dependencies(config.secret_storage)
    )
    secret_dependencies.validate()
    production_dependencies = BridgeProductionDependencies(
        pairing_exchange_key=secret_dependencies.pairing_exchange_key,
        request_credential_resolver=secret_dependencies.request_credential_resolver,
        command_credential_resolver=secret_dependencies.command_credential_resolver,
        oauth_token_verifier=oauth_token_verifier,
    )
    production_dependencies.validate()

    assembly = assemble_production_bridge(
        config.production,
        production_dependencies,
    )

    # Second gate: fail closed if assembly construction crossed an unexpected
    # identity boundary before the service runtime object can be published.
    prove_hms_bridge_runtime_identity(config.expected_service_sid)

    return BridgeProductionServiceRuntime(
        config=config,
        assembly=assembly,
        mcp_server_factory=mcp_server_factory or _default_mcp_asgi_server_factory,
    )
