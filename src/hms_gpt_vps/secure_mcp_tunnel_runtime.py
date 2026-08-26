from __future__ import annotations

from dataclasses import dataclass, field
import math
import os
from pathlib import Path, PureWindowsPath
import secrets
import subprocess
import time
from typing import Callable, Mapping, Protocol

from .bridge_runtime_layout_provisioning import DEFAULT_BRIDGE_RUNTIME_ROOT
from .bridge_service_identity import prove_hms_bridge_runtime_identity, require_hms_bridge_service_sid
from .bridge_service_secret_storage import BridgeServiceSecretStorageConfig, prove_bridge_service_secret_storage
from .qualification_file_authority import lexical_absolute, path_chain_has_redirect
from .secure_mcp_tunnel import HMS_MCP_SERVER_URL, TunnelRuntimeApiKeyStore, build_tunnel_child_environment, build_tunnel_launch_spec
from .secure_mcp_tunnel_health import TunnelHealthError, TunnelHealthResponse, default_health_probe, parse_health_base_url, readiness_response_is_ready
from .secure_mcp_tunnel_package import TunnelRuntimePackageConfig, prove_installed_tunnel_runtime

_HEALTH_DIR = "tunnel-health"
_HEALTH_FILE = "health-url.txt"
_HEALTH_LISTEN = "127.0.0.1:0"


class SecureMcpTunnelRuntimeError(RuntimeError):
    pass


class StopSignal(Protocol):
    def is_set(self) -> bool: ...
    def wait(self, timeout: float | None=None) -> bool: ...


class TunnelProcess(Protocol):
    pid: int
    def poll(self) -> int | None: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...
    def wait(self, timeout: float | None=None) -> int: ...


ProcessFactory = Callable[[tuple[str,...], Mapping[str,str], Path], TunnelProcess]
HealthProbe = Callable[[str,float], TunnelHealthResponse]


@dataclass(frozen=True)
class SecureMcpTunnelRuntimeConfig:
    expected_service_sid: str
    secret_storage: BridgeServiceSecretStorageConfig
    tunnel_id: str
    package: TunnelRuntimePackageConfig = field(default_factory=TunnelRuntimePackageConfig)
    runtime_root: Path = DEFAULT_BRIDGE_RUNTIME_ROOT
    startup_timeout_seconds: float = 60.0
    shutdown_timeout_seconds: float = 15.0
    probe_interval_seconds: float = 0.10
    steady_probe_interval_seconds: float = 1.0
    mcp_startup_wait_seconds: int = 30

    def validate(self) -> None:
        sid=require_hms_bridge_service_sid(self.expected_service_sid)
        if not isinstance(self.secret_storage,BridgeServiceSecretStorageConfig): raise TypeError("secret_storage must be a BridgeServiceSecretStorageConfig")
        self.secret_storage.validate()
        if self.secret_storage.bridge_reader_sid!=sid: raise SecureMcpTunnelRuntimeError("tunnel secret reader SID differs from HMSBridge service authority")
        if not isinstance(self.package,TunnelRuntimePackageConfig): raise TypeError("package must be a TunnelRuntimePackageConfig")
        self.package.validate()
        if not isinstance(self.runtime_root,Path) or str(PureWindowsPath(str(self.runtime_root))).casefold()!=str(PureWindowsPath(str(DEFAULT_BRIDGE_RUNTIME_ROOT))).casefold(): raise SecureMcpTunnelRuntimeError("tunnel runtime_root differs from fixed Bridge runtime authority")
        if not isinstance(self.tunnel_id,str) or len(self.tunnel_id)!=39 or not self.tunnel_id.startswith("tunnel_") or any(c not in "0123456789abcdef" for c in self.tunnel_id[7:]): raise SecureMcpTunnelRuntimeError("CONTROL_PLANE_TUNNEL_ID is invalid")
        for value,name,low,high in ((self.startup_timeout_seconds,"startup_timeout_seconds",1,300),(self.shutdown_timeout_seconds,"shutdown_timeout_seconds",1,120),(self.probe_interval_seconds,"probe_interval_seconds",.02,5),(self.steady_probe_interval_seconds,"steady_probe_interval_seconds",.1,30)):
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(float(value)) or not low<=float(value)<=high: raise SecureMcpTunnelRuntimeError(f"{name} is outside bounded authority")
        if isinstance(self.mcp_startup_wait_seconds,bool) or not isinstance(self.mcp_startup_wait_seconds,int) or not 1<=self.mcp_startup_wait_seconds<=120: raise SecureMcpTunnelRuntimeError("mcp_startup_wait_seconds is invalid")


@dataclass(frozen=True)
class SecureMcpTunnelRuntimeEvidence:
    ready: bool
    process_id: int
    executable_path: str
    executable_sha256: str
    health_base_url: str
    readiness_url: str
    mcp_server_url: str
    restart_policy: str = "fail-closed-to-HMSBridge-SCM"


def _default_process_factory(argv: tuple[str,...], environment: Mapping[str,str], cwd: Path) -> TunnelProcess:
    if not argv or not all(isinstance(v,str) and v for v in argv): raise SecureMcpTunnelRuntimeError("tunnel process argv is invalid")
    if not cwd.is_dir() or path_chain_has_redirect(cwd): raise SecureMcpTunnelRuntimeError("tunnel process cwd is not a stable directory")
    flags=int(getattr(subprocess,"CREATE_NO_WINDOW",0))
    return subprocess.Popen(list(argv),cwd=str(cwd),env=dict(environment),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,shell=False,close_fds=True,creationflags=flags)


@dataclass
class SecureMcpTunnelRuntime:
    config: SecureMcpTunnelRuntimeConfig
    process_factory: ProcessFactory = _default_process_factory
    health_probe: HealthProbe = default_health_probe
    _process: TunnelProcess|None = field(init=False,default=None,repr=False)
    _health_attempt: Path|None = field(init=False,default=None,repr=False)
    _health_base_url: str|None = field(init=False,default=None,repr=False)
    _exe_sha: str|None = field(init=False,default=None,repr=False)
    _started: bool = field(init=False,default=False,repr=False)
    _closed: bool = field(init=False,default=False,repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.config,SecureMcpTunnelRuntimeConfig): raise TypeError("config must be a SecureMcpTunnelRuntimeConfig")
        if not callable(self.process_factory) or not callable(self.health_probe): raise TypeError("runtime factories must be callable")
        self.config.validate()

    @property
    def ready(self) -> bool:
        return self._started and not self._closed and self._process is not None and self._process.poll() is None and self._health_base_url is not None

    def _health_parent(self) -> Path:
        root=lexical_absolute(self.config.runtime_root)
        if path_chain_has_redirect(root) or not root.is_dir(): raise SecureMcpTunnelRuntimeError("Bridge runtime root is missing or redirected")
        parent=root/_HEALTH_DIR
        if parent.exists() and (not parent.is_dir() or path_chain_has_redirect(parent)): raise SecureMcpTunnelRuntimeError("tunnel health parent is invalid")
        if not parent.exists(): os.mkdir(parent)
        if path_chain_has_redirect(parent): raise SecureMcpTunnelRuntimeError("tunnel health parent traverses a redirect")
        return parent

    def _prepare_handshake(self) -> Path:
        parent=self._health_parent(); attempt=parent/f"attempt-{secrets.token_hex(16)}"
        if attempt.exists() or path_chain_has_redirect(attempt): raise SecureMcpTunnelRuntimeError("tunnel health attempt is not new")
        os.mkdir(attempt); self._health_attempt=attempt; return attempt/_HEALTH_FILE

    def _cleanup_handshake(self) -> None:
        attempt=self._health_attempt
        if attempt is None: return
        try:
            if path_chain_has_redirect(attempt): raise SecureMcpTunnelRuntimeError("tunnel health attempt changed to a redirect")
            if attempt.exists():
                for entry in attempt.iterdir():
                    if entry.name!=_HEALTH_FILE or entry.is_symlink() or not entry.is_file(): raise SecureMcpTunnelRuntimeError("tunnel health attempt contains an unexpected entry")
                    entry.unlink(missing_ok=True)
                attempt.rmdir()
            parent=attempt.parent
            if parent.is_dir() and not any(parent.iterdir()): parent.rmdir()
        finally: self._health_attempt=None

    def _probe(self,url:str,*,startup:bool) -> bool:
        try: response=self.health_probe(url,min(2.0,float(self.config.probe_interval_seconds)*5.0))
        except (OSError,TimeoutError,TunnelHealthError):
            if startup: return False
            raise SecureMcpTunnelRuntimeError("tunnel readiness probe became unreachable")
        if readiness_response_is_ready(response): return True
        if startup and response.status_code==503: return False
        raise SecureMcpTunnelRuntimeError(f"tunnel readiness failed with HTTP {response.status_code}")

    def start(self, stop: StopSignal) -> bool:
        if not hasattr(stop,"is_set") or not hasattr(stop,"wait"): raise TypeError("stop must implement is_set/wait")
        self.config.validate()
        if self._closed: raise SecureMcpTunnelRuntimeError("tunnel runtime is already closed")
        if self._started or self._process is not None: raise SecureMcpTunnelRuntimeError("tunnel runtime is already starting or started")
        if stop.is_set(): return False
        prove_hms_bridge_runtime_identity(self.config.expected_service_sid)
        prove_bridge_service_secret_storage(self.config.secret_storage,require_pairing_key=True)
        package=prove_installed_tunnel_runtime(self.config.package,service_sid=self.config.expected_service_sid,prove_acl=True)
        executable=lexical_absolute(Path(package.executable_path)); launch=build_tunnel_launch_spec(executable,self.config.tunnel_id)
        api_key=TunnelRuntimeApiKeyStore(self.config.secret_storage).load()
        child_env=build_tunnel_child_environment(os.environ,tunnel_id=self.config.tunnel_id,api_key=api_key)
        try:
            url_file=self._prepare_handshake()
            argv=launch.argv+("--health.listen-addr",_HEALTH_LISTEN,"--health.url-file",str(url_file),"--mcp.startup-wait-timeout",f"{self.config.mcp_startup_wait_seconds}s")
            self._process=self.process_factory(argv,child_env,lexical_absolute(self.config.package.install_root))
            if self._process is None or isinstance(self._process.pid,bool) or not isinstance(self._process.pid,int) or self._process.pid<=0: raise SecureMcpTunnelRuntimeError("tunnel process returned an invalid PID")
            deadline=time.monotonic()+float(self.config.startup_timeout_seconds)
            while True:
                if self._process.poll() is not None: raise SecureMcpTunnelRuntimeError("tunnel process exited before readiness completed")
                if stop.is_set(): self.shutdown(); return False
                if url_file.is_file():
                    base=parse_health_base_url(url_file); ready_url=base+"/readyz"
                    if self._probe(ready_url,startup=True):
                        if self._process.poll() is not None: raise SecureMcpTunnelRuntimeError("tunnel process exited at readiness boundary")
                        prove_hms_bridge_runtime_identity(self.config.expected_service_sid)
                        prove_installed_tunnel_runtime(self.config.package,service_sid=self.config.expected_service_sid,prove_acl=True)
                        if stop.is_set(): self.shutdown(); return False
                        self._health_base_url=base; self._exe_sha=package.executable_sha256; self._started=True; return True
                if time.monotonic()>=deadline: raise SecureMcpTunnelRuntimeError("tunnel runtime did not reach /readyz within bounded startup")
                stop.wait(float(self.config.probe_interval_seconds))
        except BaseException:
            try: self.shutdown()
            except Exception as exc: raise SecureMcpTunnelRuntimeError("tunnel startup failed and shutdown also failed") from exc
            raise
        finally:
            child_env["CONTROL_PLANE_API_KEY"]=""; api_key=""

    def evidence(self) -> SecureMcpTunnelRuntimeEvidence:
        if not self.ready: raise SecureMcpTunnelRuntimeError("tunnel runtime is not ready")
        assert self._process is not None and self._health_base_url is not None and self._exe_sha is not None
        return SecureMcpTunnelRuntimeEvidence(True,self._process.pid,str(self.config.package.executable_path),self._exe_sha,self._health_base_url,self._health_base_url+"/readyz",HMS_MCP_SERVER_URL)

    def assert_healthy(self) -> None:
        if not self._started or self._closed or self._process is None or self._health_base_url is None:
            raise SecureMcpTunnelRuntimeError("tunnel runtime is not ready")
        code=self._process.poll()
        if code is not None:
            raise SecureMcpTunnelRuntimeError(f"tunnel process exited unexpectedly with code {code}")
        self._probe(self._health_base_url+"/readyz",startup=False)

    def wait(self, stop: StopSignal) -> None:
        if not self._started or self._closed or self._process is None or self._health_base_url is None: raise SecureMcpTunnelRuntimeError("tunnel runtime is not ready")
        code=self._process.poll()
        if code is not None: raise SecureMcpTunnelRuntimeError(f"tunnel process exited unexpectedly with code {code}")
        url=self._health_base_url+"/readyz"
        while not stop.wait(float(self.config.steady_probe_interval_seconds)):
            code=self._process.poll()
            if code is not None: raise SecureMcpTunnelRuntimeError(f"tunnel process exited unexpectedly with code {code}")
            if not self._probe(url,startup=False): raise SecureMcpTunnelRuntimeError("tunnel runtime lost readiness")

    def shutdown(self) -> None:
        if self._closed: return
        first: BaseException|None=None; process=self._process
        if process is not None and process.poll() is None:
            try:
                process.terminate()
                try: process.wait(timeout=float(self.config.shutdown_timeout_seconds))
                except (subprocess.TimeoutExpired,TimeoutError): process.kill(); process.wait(timeout=float(self.config.shutdown_timeout_seconds))
            except BaseException as exc: first=exc
        self._process=None; self._started=False; self._health_base_url=None; self._exe_sha=None
        try: self._cleanup_handshake()
        except BaseException as exc:
            if first is None: first=exc
        self._closed=True
        if first is not None: raise SecureMcpTunnelRuntimeError("tunnel runtime did not stop within bounded shutdown") from first

    def run(self, stop: StopSignal) -> None:
        """No blind child restart; failure bubbles to HMSBridge SCM recovery."""
        try:
            if self.start(stop): self.wait(stop)
        finally: self.shutdown()
