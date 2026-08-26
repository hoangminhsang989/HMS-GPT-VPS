from __future__ import annotations

from dataclasses import dataclass, field
from threading import Event, Thread
import re
import time
from typing import Any, Callable, Protocol

from mcp.server.auth.provider import TokenVerifier

from .agent_bridge_production_tls import AgentBridgeProductionTlsConfig, AgentBridgeProductionTlsRuntime, start_agent_bridge_production_tls
from .bridge_production_assembly import BridgeProductionAssembly, BridgeProductionConfig, BridgeProductionDependencies, assemble_production_bridge
from .bridge_service_dependency_loader import BridgeServiceSecretDependencies, load_bridge_service_secret_dependencies
from .bridge_service_identity import prove_hms_bridge_runtime_identity, require_hms_bridge_service_sid
from .bridge_service_secret_storage import BridgeServiceSecretStorageConfig
from .secure_mcp_tunnel_runtime import SecureMcpTunnelRuntime, SecureMcpTunnelRuntimeConfig

_LOOPBACK_HOST = "127.0.0.1"
_MCP_PATH = "/mcp"
_DEFAULT_STARTUP_TIMEOUT_SECONDS = 30
_DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 30
_TUNNEL_HEALTH_INTERVAL_SECONDS = 1.0
_TUNNEL_ID_RE = re.compile(r"^tunnel_[0-9a-f]{32}$")


class BridgeProductionServiceRuntimeError(RuntimeError):
    pass


class McpAsgiServer(Protocol):
    started: bool
    should_exit: bool
    force_exit: bool
    def run(self) -> None: ...


class TunnelRuntime(Protocol):
    @property
    def ready(self) -> bool: ...
    def start(self, stop: Event) -> bool: ...
    def assert_healthy(self) -> None: ...
    def shutdown(self) -> None: ...


McpAsgiServerFactory = Callable[[Any, str, int], McpAsgiServer]
TunnelRuntimeFactory = Callable[["BridgeProductionServiceRuntimeConfig"], TunnelRuntime]


@dataclass(frozen=True)
class BridgeProductionServiceRuntimeConfig:
    expected_service_sid: str
    secret_storage: BridgeServiceSecretStorageConfig
    production: BridgeProductionConfig
    tls: AgentBridgeProductionTlsConfig
    tunnel_id: str
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
        self.secret_storage.validate(); self.production.validate(); self.tls.validate()
        if not isinstance(self.tunnel_id, str) or _TUNNEL_ID_RE.fullmatch(self.tunnel_id) is None:
            raise BridgeProductionServiceRuntimeError("tunnel_id differs from canonical OpenAI tunnel authority")
        if self.production.mcp.port != 8765:
            raise BridgeProductionServiceRuntimeError("production MCP port must remain 8765 for fixed tunnel authority")
        if self.secret_storage.bridge_reader_sid != expected_sid:
            raise BridgeProductionServiceRuntimeError("service secret reader SID differs from HMSBridge service authority")
        if self.tls.storage.bridge_reader_sid != expected_sid:
            raise BridgeProductionServiceRuntimeError("TLS private-key reader SID differs from HMSBridge service authority")
        runtime_secrets = self.production.runtime_root.expanduser().absolute() / "secrets"
        secret_parent = self.secret_storage.root.expanduser().absolute().parent
        if secret_parent != runtime_secrets:
            raise BridgeProductionServiceRuntimeError("service secret root is outside the production Bridge secrets directory")
        for value, name in ((self.startup_timeout_seconds, "startup_timeout_seconds"),(self.shutdown_timeout_seconds, "shutdown_timeout_seconds")):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 300:
                raise BridgeProductionServiceRuntimeError(f"{name} must be an integer from 1 through 300")


def _default_mcp_asgi_server_factory(mcp_server: Any, host: str, port: int) -> McpAsgiServer:
    if host != _LOOPBACK_HOST:
        raise BridgeProductionServiceRuntimeError("production MCP ASGI server must bind exact loopback")
    try: import uvicorn
    except ImportError as exc:
        raise BridgeProductionServiceRuntimeError("uvicorn is required by the Bridge production MCP runtime") from exc
    app = mcp_server.streamable_http_app(host=_LOOPBACK_HOST, streamable_http_path=_MCP_PATH, stateless_http=True, json_response=True)
    return uvicorn.Server(uvicorn.Config(app=app, host=_LOOPBACK_HOST, port=port, log_level="warning", access_log=False, lifespan="on"))


def _default_tunnel_runtime_factory(config: BridgeProductionServiceRuntimeConfig) -> TunnelRuntime:
    config.validate()
    tunnel_config = SecureMcpTunnelRuntimeConfig(
        expected_service_sid=config.expected_service_sid,
        secret_storage=config.secret_storage,
        tunnel_id=config.tunnel_id,
        runtime_root=config.production.runtime_root,
        startup_timeout_seconds=float(config.startup_timeout_seconds),
        shutdown_timeout_seconds=float(min(config.shutdown_timeout_seconds, 120)),
    )
    tunnel_config.validate()
    return SecureMcpTunnelRuntime(tunnel_config)


@dataclass
class BridgeProductionServiceRuntime:
    config: BridgeProductionServiceRuntimeConfig
    assembly: BridgeProductionAssembly
    mcp_server_factory: McpAsgiServerFactory = _default_mcp_asgi_server_factory
    tunnel_runtime_factory: TunnelRuntimeFactory = _default_tunnel_runtime_factory
    _tls_runtime: AgentBridgeProductionTlsRuntime | None = field(init=False, default=None, repr=False)
    _mcp_thread: Thread | None = field(init=False, default=None, repr=False)
    _mcp_server: McpAsgiServer | None = field(init=False, default=None, repr=False)
    _mcp_error: list[BaseException] = field(init=False, default_factory=list, repr=False)
    _tunnel_runtime: TunnelRuntime | None = field(init=False, default=None, repr=False)
    _started: bool = field(init=False, default=False, repr=False)
    _closed: bool = field(init=False, default=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.config, BridgeProductionServiceRuntimeConfig): raise TypeError("config must be a BridgeProductionServiceRuntimeConfig")
        if not isinstance(self.assembly, BridgeProductionAssembly): raise TypeError("assembly must be a BridgeProductionAssembly")
        if not callable(self.mcp_server_factory) or not callable(self.tunnel_runtime_factory): raise TypeError("runtime factories must be callable")
        self.config.validate()
        if self.assembly.config != self.config.production:
            raise BridgeProductionServiceRuntimeError("Bridge assembly config differs from service runtime authority")

    @property
    def ready(self) -> bool:
        return self._started and not self._closed and self._tunnel_runtime is not None and self._tunnel_runtime.ready

    def _stop_mcp_server(self, server: McpAsgiServer, thread: Thread) -> None:
        server.should_exit = True; thread.join(timeout=float(self.config.shutdown_timeout_seconds))
        if thread.is_alive(): server.force_exit = True; thread.join(timeout=float(self.config.shutdown_timeout_seconds))
        if thread.is_alive(): raise BridgeProductionServiceRuntimeError("MCP ASGI server thread did not stop within bounded shutdown")

    def _assert_local_runtime_healthy(self, mcp_thread: Thread, tls_runtime: AgentBridgeProductionTlsRuntime) -> None:
        if self._mcp_error:
            raise BridgeProductionServiceRuntimeError("MCP ASGI server failed while service was running") from self._mcp_error[0]
        if not mcp_thread.is_alive():
            raise BridgeProductionServiceRuntimeError("MCP ASGI server exited before SCM stop")
        expected_tls=(self.config.tls.firewall.network.gateway,self.config.tls.firewall.port)
        if tls_runtime.bound_address != expected_tls:
            raise BridgeProductionServiceRuntimeError("production Agent TLS listener lost exact authority")

    def start(self, stop: Event) -> bool:
        if not isinstance(stop, Event): raise TypeError("stop must be a threading.Event")
        self.config.validate()
        if self._closed: raise BridgeProductionServiceRuntimeError("production Bridge runtime is already closed")
        if self._started or any(v is not None for v in (self._tls_runtime,self._mcp_thread,self._mcp_server,self._tunnel_runtime)):
            raise BridgeProductionServiceRuntimeError("production Bridge runtime is already starting or started")
        if stop.is_set(): return False
        prove_hms_bridge_runtime_identity(self.config.expected_service_sid)
        try:
            tls_runtime=start_agent_bridge_production_tls(self.assembly.agent_http,self.config.tls); self._tls_runtime=tls_runtime
            expected_tls=(self.config.tls.firewall.network.gateway,self.config.tls.firewall.port)
            if tls_runtime.bound_address != expected_tls: raise BridgeProductionServiceRuntimeError("production Agent TLS runtime returned the wrong bind authority")
            mcp_server=self.mcp_server_factory(self.assembly.mcp_server,_LOOPBACK_HOST,self.config.production.mcp.port)
            for attr in ("run","started","should_exit","force_exit"):
                if not hasattr(mcp_server,attr): raise BridgeProductionServiceRuntimeError("MCP ASGI server factory returned an invalid server")
            self._mcp_server=mcp_server; self._mcp_error.clear()
            def run_mcp() -> None:
                try: mcp_server.run()
                except BaseException as exc: self._mcp_error.append(exc)
            mcp_thread=Thread(target=run_mcp,name="HMSBridgeMCP",daemon=False); self._mcp_thread=mcp_thread; mcp_thread.start()
            deadline=time.monotonic()+self.config.startup_timeout_seconds
            while not bool(mcp_server.started):
                if self._mcp_error: raise BridgeProductionServiceRuntimeError("MCP ASGI server failed during startup") from self._mcp_error[0]
                if not mcp_thread.is_alive(): raise BridgeProductionServiceRuntimeError("MCP ASGI server exited before startup completed")
                if stop.is_set(): self.shutdown(); return False
                if time.monotonic()>=deadline: raise BridgeProductionServiceRuntimeError("MCP ASGI server did not report startup within bounded time")
                stop.wait(0.05)
            self._assert_local_runtime_healthy(mcp_thread,tls_runtime)
            if stop.is_set(): self.shutdown(); return False
            tunnel=self.tunnel_runtime_factory(self.config)
            for attr in ("start","ready","assert_healthy","shutdown"):
                if not hasattr(tunnel,attr): raise BridgeProductionServiceRuntimeError("tunnel runtime factory returned an invalid runtime")
            self._tunnel_runtime=tunnel
            if not tunnel.start(stop): self.shutdown(); return False
            if not tunnel.ready: raise BridgeProductionServiceRuntimeError("secure MCP tunnel did not reach exact readiness")
            self._assert_local_runtime_healthy(mcp_thread,tls_runtime); tunnel.assert_healthy()
            prove_hms_bridge_runtime_identity(self.config.expected_service_sid)
            if stop.is_set(): self.shutdown(); return False
            self._started=True; return True
        except BaseException:
            try: self.shutdown()
            except Exception as shutdown_exc: raise BridgeProductionServiceRuntimeError("production Bridge startup failed and shutdown also failed") from shutdown_exc
            raise

    def wait(self, stop: Event) -> None:
        if not isinstance(stop, Event): raise TypeError("stop must be a threading.Event")
        if not self.ready: raise BridgeProductionServiceRuntimeError("production Bridge runtime is not ready")
        mcp_thread=self._mcp_thread; tls_runtime=self._tls_runtime; tunnel=self._tunnel_runtime
        if mcp_thread is None or tls_runtime is None or tunnel is None: raise BridgeProductionServiceRuntimeError("production Bridge runtime lost owned listener state")
        next_tunnel_probe=time.monotonic()
        while not stop.wait(0.20):
            self._assert_local_runtime_healthy(mcp_thread,tls_runtime)
            if time.monotonic()>=next_tunnel_probe:
                try: tunnel.assert_healthy()
                except BaseException as exc: raise BridgeProductionServiceRuntimeError("secure MCP tunnel failed while service was running") from exc
                next_tunnel_probe=time.monotonic()+_TUNNEL_HEALTH_INTERVAL_SECONDS

    def shutdown(self) -> None:
        if self._closed: return
        first_error: BaseException|None=None
        tunnel=self._tunnel_runtime; server=self._mcp_server; thread=self._mcp_thread; tls_runtime=self._tls_runtime
        if tunnel is not None:
            try: tunnel.shutdown()
            except BaseException as exc: first_error=exc
        if server is not None and thread is not None and thread.is_alive():
            try: self._stop_mcp_server(server,thread)
            except BaseException as exc:
                if first_error is None: first_error=exc
        if self._mcp_error and first_error is None: first_error=self._mcp_error[0]
        try:
            if tls_runtime is not None: tls_runtime.shutdown()
        except BaseException as exc:
            if first_error is None: first_error=exc
        finally:
            self._tunnel_runtime=None; self._mcp_server=None; self._mcp_thread=None; self._tls_runtime=None; self._started=False; self._closed=True
        if first_error is not None: raise BridgeProductionServiceRuntimeError("production Bridge runtime shutdown failed") from first_error

    def run(self, stop: Event) -> None:
        try:
            if self.start(stop): self.wait(stop)
        finally: self.shutdown()


def build_bridge_production_service_runtime(
    config: BridgeProductionServiceRuntimeConfig,
    oauth_token_verifier: TokenVerifier,
    *,
    mcp_server_factory: McpAsgiServerFactory | None = None,
    tunnel_runtime_factory: TunnelRuntimeFactory | None = None,
) -> BridgeProductionServiceRuntime:
    if not isinstance(config, BridgeProductionServiceRuntimeConfig): raise TypeError("config must be a BridgeProductionServiceRuntimeConfig")
    if not callable(getattr(oauth_token_verifier,"verify_token",None)): raise TypeError("oauth_token_verifier must implement verify_token")
    config.validate(); prove_hms_bridge_runtime_identity(config.expected_service_sid)
    secret_dependencies: BridgeServiceSecretDependencies=load_bridge_service_secret_dependencies(config.secret_storage); secret_dependencies.validate()
    production_dependencies=BridgeProductionDependencies(
        pairing_exchange_key=secret_dependencies.pairing_exchange_key,
        request_credential_resolver=secret_dependencies.request_credential_resolver,
        command_credential_resolver=secret_dependencies.command_credential_resolver,
        oauth_token_verifier=oauth_token_verifier,
    ); production_dependencies.validate()
    assembly=assemble_production_bridge(config.production,production_dependencies)
    prove_hms_bridge_runtime_identity(config.expected_service_sid)
    return BridgeProductionServiceRuntime(
        config=config,
        assembly=assembly,
        mcp_server_factory=mcp_server_factory or _default_mcp_asgi_server_factory,
        tunnel_runtime_factory=tunnel_runtime_factory or _default_tunnel_runtime_factory,
    )
