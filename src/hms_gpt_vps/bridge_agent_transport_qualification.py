from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Callable

from .agent_command_store import AgentCommandState, AgentCommandStore
from .agent_runtime_runner import AgentRuntimeRunnerConfig
from .agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandEnvelope,
    sign_bridge_command,
)
from .bridge_activation_qualification import (
    _load_and_verify_package,
    start_hms_bridge_for_qualification,
    stop_hms_bridge_after_qualification,
)
from .bridge_host_deployment_transaction import derive_hms_bridge_service_sid
from .bridge_service_config_storage import load_protected_bridge_service_runtime_config
from .bridge_service_machine_secrets import BridgeServiceAgentCredentialResolver
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .bridge_service_runtime_config import BridgeServiceRuntimeConfig
from .bridge_service_secret_storage import prove_bridge_service_secret_storage
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json_by_id
from .qualification_file_authority import path_chain_has_redirect

_HMS_AGENT_SERVICE_NAME = "HMSAgent"
_HMS_AGENT_SERVICE_ACCOUNT = r"NT AUTHORITY\LocalService"
_HMS_AGENT_RUNTIME_IDENTITY = r"NT SERVICE\HMSAgent"
_AGENT_RUNTIME_CONFIG_PATH = r"C:\ProgramData\HMS-GPT-VPS\Agent\agent-runtime.json"
_AGENT_HEALTH_PATH = "/healthz"
_HEARTBEAT_INTERVAL_SECONDS = AgentRuntimeRunnerConfig().heartbeat_interval_seconds
_HEARTBEAT_PROOF_MARGIN_SECONDS = 3.0
_HELLO_TIMEOUT_SECONDS = 45.0
_COMMAND_TIMEOUT_SECONDS = 45.0
_POLL_INTERVAL_SECONDS = 0.25
_COMMAND_DEADLINE_SECONDS = 60
_QUALIFICATION_ACTION = "git.status"
_GUEST_KEYS = frozenset({
    "ready", "service_name", "service_state", "service_start_mode",
    "service_start_name", "process_id", "config_instance_id",
    "config_bridge_origin", "config_workspace_root", "health_port",
    "health_status", "health_instance_id", "health_workspace_root",
    "health_boot_id", "health_service_identity", "health_privilege",
    "health_listener_scope",
})


class BridgeAgentTransportQualificationError(RuntimeError):
    pass


@dataclass(frozen=True)
class BridgeAgentTransportQualificationRequest:
    guest_credential: PowerShellDirectCredential
    hello_timeout_seconds: float = _HELLO_TIMEOUT_SECONDS
    heartbeat_margin_seconds: float = _HEARTBEAT_PROOF_MARGIN_SECONDS
    command_timeout_seconds: float = _COMMAND_TIMEOUT_SECONDS

    def validate(self) -> None:
        if not isinstance(self.guest_credential, PowerShellDirectCredential):
            raise TypeError("guest_credential must be a PowerShellDirectCredential")
        self.guest_credential.validate()
        for name, value, lower, upper in (
            ("hello_timeout_seconds", self.hello_timeout_seconds, 5.0, 120.0),
            ("heartbeat_margin_seconds", self.heartbeat_margin_seconds, 1.0, 30.0),
            ("command_timeout_seconds", self.command_timeout_seconds, 5.0, 120.0),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric")
            if not lower <= float(value) <= upper:
                raise ValueError(f"{name} is outside qualification bounds")


@dataclass(frozen=True)
class _Presence:
    instance_id: str
    device_id: str
    boot_id: str
    connection_epoch: int
    first_seen_unix: float
    last_seen_unix: float


def _same_identity(left, right) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _read_presence_read_only(path: Path, instance_id: str) -> _Presence | None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise BridgeAgentTransportQualificationError("presence database path is invalid")
    if path_chain_has_redirect(path):
        raise BridgeAgentTransportQualificationError("presence database traverses a redirect")
    if not path.is_file():
        return None
    before = path.stat()
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=5.0)
    try:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """SELECT instance_id, device_id, boot_id, connection_epoch,
                      first_seen_unix, last_seen_unix
               FROM agent_presence WHERE instance_id = ?""",
            (instance_id,),
        ).fetchone()
    finally:
        connection.close()
    if path_chain_has_redirect(path):
        raise BridgeAgentTransportQualificationError("presence database changed to a redirect")
    if not _same_identity(before, path.stat()):
        raise BridgeAgentTransportQualificationError("presence database identity changed")
    if row is None:
        return None
    required = {"instance_id", "device_id", "boot_id", "connection_epoch", "first_seen_unix", "last_seen_unix"}
    if set(row.keys()) != required:
        raise BridgeAgentTransportQualificationError("presence row schema differs")
    texts = {key: row[key] for key in ("instance_id", "device_id", "boot_id")}
    if any(not isinstance(value, str) or not value for value in texts.values()):
        raise BridgeAgentTransportQualificationError("presence identity is invalid")
    epoch = row["connection_epoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
        raise BridgeAgentTransportQualificationError("presence epoch is invalid")
    first, last = row["first_seen_unix"], row["last_seen_unix"]
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(float(v)) for v in (first, last)):
        raise BridgeAgentTransportQualificationError("presence timestamps are invalid")
    if float(last) < float(first):
        raise BridgeAgentTransportQualificationError("presence timestamps are inconsistent")
    return _Presence(texts["instance_id"], texts["device_id"], texts["boot_id"], epoch, float(first), float(last))


def build_guest_hms_agent_observation_script() -> str:
    service_name = ps_literal(_HMS_AGENT_SERVICE_NAME)
    config_path = ps_literal(_AGENT_RUNTIME_CONFIG_PATH)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$configPath = [System.IO.Path]::GetFullPath({config_path})
$rows = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSAgent service' }}
$service = $rows[0]
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {{ throw 'HMSAgent runtime config is missing' }}
$config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
$port = [int]$config.health_port
if ($port -lt 1024 -or $port -gt 65535) {{ throw 'HMSAgent health port is invalid' }}
$health = Invoke-RestMethod -Method Get -Uri ("http://127.0.0.1:" + $port + "{_AGENT_HEALTH_PATH}") -TimeoutSec 5
[pscustomobject]@{{
  ready = $true
  service_name = [string]$service.Name
  service_state = [string]$service.State
  service_start_mode = [string]$service.StartMode
  service_start_name = [string]$service.StartName
  process_id = [int]$service.ProcessId
  config_instance_id = [string]$config.instance_id
  config_bridge_origin = [string]$config.bridge_origin
  config_workspace_root = [string]$config.workspace_root
  health_port = [int]$port
  health_status = [string]$health.status
  health_instance_id = [string]$health.instance_id
  health_workspace_root = [string]$health.workspace_root
  health_boot_id = [string]$health.boot_id
  health_service_identity = [string]$health.service_identity
  health_privilege = [string]$health.privilege
  health_listener_scope = [string]$health.listener_scope
}}
""".strip()


def _observe_guest_agent(config: BridgeServiceRuntimeConfig, credential: PowerShellDirectCredential) -> dict[str, object]:
    result = run_vm_powershell_json_by_id(
        config.vm_id, config.vm_name, credential,
        build_guest_hms_agent_observation_script(), timeout_seconds=30,
    )
    if frozenset(result) != _GUEST_KEYS:
        raise BridgeAgentTransportQualificationError("HMSAgent observation schema differs")
    expected = {
        "ready": True,
        "service_name": _HMS_AGENT_SERVICE_NAME,
        "service_state": "Running",
        "service_start_name": _HMS_AGENT_SERVICE_ACCOUNT,
        "config_instance_id": config.instance_id,
        "config_bridge_origin": f"https://172.29.240.1:{config.tls_port}",
        "health_status": "ok",
        "health_instance_id": config.instance_id,
        "health_service_identity": _HMS_AGENT_RUNTIME_IDENTITY,
        "health_privilege": "non-admin",
        "health_listener_scope": "loopback-only",
    }
    for key, wanted in expected.items():
        observed = result.get(key)
        if isinstance(wanted, str):
            if not isinstance(observed, str) or observed.casefold() != wanted.casefold():
                raise BridgeAgentTransportQualificationError(f"HMSAgent observation differs: {key}")
        elif observed is not wanted:
            raise BridgeAgentTransportQualificationError(f"HMSAgent observation differs: {key}")
    if result.get("service_start_mode") not in {"Auto", "Automatic"}:
        raise BridgeAgentTransportQualificationError("HMSAgent is not Automatic")
    pid = result.get("process_id")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise BridgeAgentTransportQualificationError("HMSAgent process id is invalid")
    boot_id = result.get("health_boot_id")
    if not isinstance(boot_id, str) or not boot_id or len(boot_id) > 128:
        raise BridgeAgentTransportQualificationError("HMSAgent health boot_id is invalid")
    workspace, health_workspace = result.get("config_workspace_root"), result.get("health_workspace_root")
    if not isinstance(workspace, str) or not isinstance(health_workspace, str) or workspace.casefold() != health_workspace.casefold():
        raise BridgeAgentTransportQualificationError("HMSAgent health workspace differs")
    return dict(result)


def _wait_for_authenticated_hello(
    path: Path, *, instance_id: str, boot_id: str, not_before_unix: float,
    timeout_seconds: float, monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> _Presence:
    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        presence = _read_presence_read_only(path, instance_id)
        if presence is not None and presence.boot_id == boot_id and presence.last_seen_unix >= not_before_unix:
            return presence
        sleeper(_POLL_INTERVAL_SECONDS)
    raise BridgeAgentTransportQualificationError("authenticated HMSAgent hello was not observed before timeout")


def _wait_for_heartbeat_generation_stability(
    path: Path, initial: _Presence, *, margin_seconds: float,
    sleeper: Callable[[float], None] = time.sleep,
) -> _Presence:
    sleeper(_HEARTBEAT_INTERVAL_SECONDS + margin_seconds)
    current = _read_presence_read_only(path, initial.instance_id)
    if current is None:
        raise BridgeAgentTransportQualificationError("Agent presence disappeared")
    if (
        current.device_id != initial.device_id
        or current.boot_id != initial.boot_id
        or current.connection_epoch != initial.connection_epoch
        or current.last_seen_unix <= initial.last_seen_unix
    ):
        raise BridgeAgentTransportQualificationError("HMSAgent generation did not remain stable across heartbeat boundary")
    return current


def _enqueue_read_only_git_status(
    config: BridgeServiceRuntimeConfig, *, service_sid: str,
    expected_device_id: str, now: datetime | None = None,
) -> tuple[AgentCommandStore, str]:
    runtime = config.to_runtime_config(service_sid)
    secret_before = prove_bridge_service_secret_storage(runtime.secret_storage, require_pairing_key=True)
    resolver = BridgeServiceAgentCredentialResolver(runtime.secret_storage)
    credential = resolver.for_command(config.instance_id)
    if credential.device_id != expected_device_id:
        raise BridgeAgentTransportQualificationError("Bridge qualification credential device_id differs from authenticated Agent")
    secret_after = prove_bridge_service_secret_storage(runtime.secret_storage, require_pairing_key=True)
    if secret_before != secret_after:
        raise BridgeAgentTransportQualificationError("Bridge service secret authority changed across qualification credential load")
    request_id = "r002fqual-" + secrets.token_urlsafe(12)
    timestamp = now or datetime.now(timezone.utc)
    command = AgentCommandEnvelope(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id=request_id,
        instance_id=config.instance_id,
        action=_QUALIFICATION_ACTION,
        params={},
        deadline_at=timestamp + timedelta(seconds=_COMMAND_DEADLINE_SECONDS),
    )
    store = AgentCommandStore(Path(config.runtime_root) / "db" / "agent-commands.sqlite3")
    status = store.enqueue(sign_bridge_command(credential, command), now=timestamp)
    if status.state is not AgentCommandState.PENDING:
        raise BridgeAgentTransportQualificationError("qualification command did not enter pending state")
    return store, request_id


def _wait_for_result(
    store: AgentCommandStore, *, instance_id: str, request_id: str,
    timeout_seconds: float, monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
):
    deadline = monotonic() + timeout_seconds
    while monotonic() < deadline:
        status = store.get_status(instance_id, request_id)
        if status is not None and status.state is AgentCommandState.COMPLETED:
            if status.result is None:
                raise BridgeAgentTransportQualificationError("completed qualification command has no result")
            result = status.result
            if result.instance_id != instance_id or result.request_id != request_id or result.outcome not in {"ok", "failed"}:
                raise BridgeAgentTransportQualificationError("qualification result identity/outcome differs")
            expected_keys = {"ok", "returncode", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "stdout_bytes", "stderr_bytes"}
            if set(result.response) != expected_keys or not isinstance(result.response.get("ok"), bool):
                raise BridgeAgentTransportQualificationError("git.status qualification result schema differs")
            return result
        if status is not None and status.state is AgentCommandState.EXPIRED:
            raise BridgeAgentTransportQualificationError("qualification command expired before Agent result")
        sleeper(_POLL_INTERVAL_SECONDS)
    raise BridgeAgentTransportQualificationError("qualification command result was not observed before timeout")


def qualify_authenticated_agent_transport(request: BridgeAgentTransportQualificationRequest) -> dict[str, object]:
    """Prove the real HMSAgent authenticated transport while leaving HMSBridge stopped."""
    request.validate()
    service_sid = derive_hms_bridge_service_sid()
    config = load_protected_bridge_service_runtime_config()
    if not isinstance(config, BridgeServiceRuntimeConfig):
        raise BridgeAgentTransportQualificationError("protected Bridge runtime config type is invalid")
    config.validate()
    config.to_runtime_config(service_sid)
    manifest = _load_and_verify_package()
    pre = prove_hms_bridge_provisioning_identity()
    if pre.get("service_sid") != service_sid or pre.get("service_state") != "Stopped" or pre.get("service_start_mode") != "Manual":
        raise BridgeAgentTransportQualificationError("HMSBridge is not exact Stopped/Manual before transport qualification")

    guest_before = _observe_guest_agent(config, request.guest_credential)
    presence_path = Path(config.runtime_root) / "db" / "agent-presence.sqlite3"
    started_at_unix = datetime.now(timezone.utc).timestamp()
    started = False
    primary_error: BaseException | None = None
    start_evidence = stop_evidence = None
    hello = heartbeat = None
    result = None
    request_id = None
    try:
        start_evidence = start_hms_bridge_for_qualification(config, manifest, service_sid)
        started = True
        hello = _wait_for_authenticated_hello(
            presence_path, instance_id=config.instance_id,
            boot_id=str(guest_before["health_boot_id"]),
            not_before_unix=started_at_unix,
            timeout_seconds=float(request.hello_timeout_seconds),
        )
        heartbeat = _wait_for_heartbeat_generation_stability(
            presence_path, hello, margin_seconds=float(request.heartbeat_margin_seconds),
        )
        guest_after_heartbeat = _observe_guest_agent(config, request.guest_credential)
        if guest_after_heartbeat["health_boot_id"] != hello.boot_id or guest_after_heartbeat["process_id"] != guest_before["process_id"]:
            raise BridgeAgentTransportQualificationError("HMSAgent process/boot changed across heartbeat qualification")
        store, request_id = _enqueue_read_only_git_status(
            config, service_sid=service_sid, expected_device_id=hello.device_id,
        )
        result = _wait_for_result(
            store, instance_id=config.instance_id, request_id=request_id,
            timeout_seconds=float(request.command_timeout_seconds),
        )
        after_result = _read_presence_read_only(presence_path, config.instance_id)
        if after_result is None or after_result.device_id != hello.device_id or after_result.boot_id != hello.boot_id or after_result.connection_epoch != hello.connection_epoch:
            raise BridgeAgentTransportQualificationError("Agent generation changed across poll/result qualification")
        guest_after_result = _observe_guest_agent(config, request.guest_credential)
        if guest_after_result["health_boot_id"] != hello.boot_id or guest_after_result["process_id"] != guest_before["process_id"]:
            raise BridgeAgentTransportQualificationError("HMSAgent process/boot changed across result qualification")
    except BaseException as exc:
        primary_error = exc
    finally:
        if started:
            try:
                stop_evidence = stop_hms_bridge_after_qualification(config, service_sid)
            except BaseException as stop_exc:
                if primary_error is None:
                    primary_error = stop_exc
                else:
                    raise BridgeAgentTransportQualificationError("transport qualification failed and HMSBridge stop also failed") from stop_exc
    if primary_error is not None:
        raise primary_error
    if any(value is None for value in (start_evidence, stop_evidence, hello, heartbeat, result, request_id)):
        raise BridgeAgentTransportQualificationError("authenticated Agent transport qualification evidence is incomplete")
    post = prove_hms_bridge_provisioning_identity()
    if post.get("service_sid") != service_sid or post.get("service_state") != "Stopped" or post.get("service_start_mode") != "Manual":
        raise BridgeAgentTransportQualificationError("HMSBridge did not return to exact Stopped/Manual")
    return {
        "ready": True,
        "status": "AUTHENTICATED_AGENT_TRANSPORT_QUALIFIED_STOPPED",
        "service_sid": service_sid,
        "service_state": "Stopped",
        "service_start_mode": "Manual",
        "runtime_process_id": start_evidence["process_id"],
        "agent_process_id": guest_before["process_id"],
        "agent_device_id": hello.device_id,
        "agent_boot_id": hello.boot_id,
        "agent_connection_epoch": hello.connection_epoch,
        "authenticated_hello_proven": True,
        "authenticated_heartbeat_proven": True,
        "authenticated_poll_proven": True,
        "authenticated_result_proven": True,
        "authenticated_agent_transport_proven": True,
        "qualification_action": _QUALIFICATION_ACTION,
        "qualification_request_id": request_id,
        "qualification_result_outcome": result.outcome,
        "listeners_absent_after_stop": True,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }
