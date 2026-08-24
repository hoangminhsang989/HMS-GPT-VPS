from __future__ import annotations

import argparse
import ctypes
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import time

from hms_gpt_vps.agent_connection_epoch_store import AgentConnectionEpochStore
from hms_gpt_vps.agent_device_credential_store import (
    GuestAgentDeviceCredentialStore,
    guest_device_credential_path,
)
from hms_gpt_vps.agent_health_contract import (
    DEFAULT_REQUIRED_CAPABILITIES,
    AgentHealthDocument,
    AgentHealthExpectation,
    parse_agent_health,
)
from hms_gpt_vps.agent_package import (
    AgentPackageManifest,
    load_agent_package_manifest,
    require_windows_amd64_pe,
    verify_agent_package,
)
from hms_gpt_vps.agent_service_install import (
    AgentServiceConfig,
    build_agent_service_install_script,
)
from hms_gpt_vps.agent_service_readiness import build_agent_service_readiness_script
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_DEVICE_SECRET_BYTES,
    AgentDeviceCredential,
)
from hms_gpt_vps.powershell import ps_literal, run_powershell_json


_INSTANCE_ID = "ci-native-scm"
_DEVICE_ID = "ci-native-device"
_PROJECT_ID = "ci-native-project"
_HEALTH_PORT = 18765
_BRIDGE_ORIGIN = "https://127.0.0.1:9"
_EPOCH_FILENAME = "agent-connection-epoch.sqlite3"
_MARKER_FILENAME = ".hms-ci-native-service-owned"
_MAX_HEALTH_BYTES = 32 * 1024


def _require_github_hosted_windows_admin() -> None:
    if os.name != "nt":
        raise OSError("native packaged Agent qualification requires Windows")
    if os.environ.get("GITHUB_ACTIONS", "").casefold() != "true":
        raise PermissionError("native packaged Agent qualification is CI-only")
    if not bool(ctypes.windll.shell32.IsUserAnAdmin()):  # type: ignore[attr-defined]
        raise PermissionError("native packaged Agent qualification requires Administrator")


def _find_git_executable() -> str:
    candidate = shutil.which("git.exe") or shutil.which("git")
    if not candidate:
        raise FileNotFoundError("git executable is unavailable on Windows runner")
    path = Path(candidate).resolve(strict=True)
    if not path.is_file():
        raise FileNotFoundError(path)
    return str(path)


def _service_exists(service_name: str) -> bool:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction SilentlyContinue
[pscustomobject]@{{ exists = [bool]($null -ne $service) }}
""".strip(),
        timeout_seconds=30,
    )
    return bool(result.get("exists", False))


def _local_health_once(port: int) -> AgentHealthDocument:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2.0)
    try:
        connection.request(
            "GET",
            "/healthz",
            headers={"Connection": "close", "Accept": "application/json"},
        )
        response = connection.getresponse()
        body = response.read(_MAX_HEALTH_BYTES + 1)
        if response.status != 200:
            raise RuntimeError(f"Agent health returned HTTP {response.status}")
        if len(body) > _MAX_HEALTH_BYTES:
            raise RuntimeError("Agent health response exceeded qualification bound")
        content_type = response.getheader("Content-Type", "")
        if not content_type.lower().startswith("application/json"):
            raise RuntimeError("Agent health response is not JSON")
    finally:
        connection.close()

    try:
        raw = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Agent health response is not valid UTF-8 JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("Agent health response must be a JSON object")
    document = parse_agent_health(
        raw,
        AgentHealthExpectation(
            instance_id=_INSTANCE_ID,
            workspace_root=r"C:\HMS-Workspace",
            required_capabilities=DEFAULT_REQUIRED_CAPABILITIES,
        ),
    )
    if document.capability_set() != DEFAULT_REQUIRED_CAPABILITIES:
        raise RuntimeError("Agent health capability set is not exact")
    return document


def _wait_for_health(version: str, *, timeout_seconds: float = 20.0) -> AgentHealthDocument:
    deadline = time.monotonic() + timeout_seconds
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            document = _local_health_once(_HEALTH_PORT)
            if document.agent_version != version:
                raise RuntimeError("packaged Agent health version mismatch")
            return document
        except (ConnectionError, OSError, RuntimeError) as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError("packaged Agent health did not become ready") from last_error


def _require_health_unreachable(*, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            _local_health_once(_HEALTH_PORT)
        except (ConnectionError, OSError, RuntimeError):
            return
        time.sleep(0.1)
    raise RuntimeError("Agent loopback health listener remained reachable after service stop")


def _probe_listener(service_name: str) -> dict[str, object]:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-CimInstance Win32_Service -Filter "Name='{service_name}'" -ErrorAction Stop
$pidValue = [int]$service.ProcessId
if ($pidValue -le 0) {{ throw 'HMS Agent service has no live process id' }}
$connections = @(
  Get-NetTCPConnection -State Listen -LocalPort {_HEALTH_PORT} -ErrorAction Stop |
    Where-Object {{ [int]$_.OwningProcess -eq $pidValue }}
)
[pscustomobject]@{{
  service_name = {name}
  process_id = $pidValue
  listener_count = [int]$connections.Count
  local_addresses = @($connections | ForEach-Object {{ $_.LocalAddress }})
}}
""".strip(),
        timeout_seconds=30,
    )
    addresses_raw = result.get("local_addresses", [])
    if isinstance(addresses_raw, str):
        addresses = [addresses_raw]
    elif isinstance(addresses_raw, list):
        addresses = [str(value) for value in addresses_raw]
    else:
        raise RuntimeError("listener address evidence has invalid shape")
    if int(result.get("listener_count", 0)) != 1:
        raise RuntimeError("Agent health must have exactly one listening socket")
    if addresses != ["127.0.0.1"]:
        raise RuntimeError("Agent health listener is not bound exclusively to IPv4 loopback")
    result["local_addresses"] = addresses
    return result


def _wait_for_epoch(
    state_root: Path,
    *,
    minimum_epoch: int,
    timeout_seconds: float = 10.0,
) -> int:
    store = AgentConnectionEpochStore(state_root / _EPOCH_FILENAME)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        record = store.load()
        if record is not None:
            if record.instance_id != _INSTANCE_ID or record.device_id != _DEVICE_ID:
                raise RuntimeError("connection epoch identity mismatch")
            if record.epoch >= minimum_epoch:
                return record.epoch
        time.sleep(0.2)
    raise RuntimeError("Agent outbound reconnect epoch did not reach expected value")


def _stop_service(service_name: str) -> None:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction Stop
if ($service.Status -ne 'Stopped') {{
  Stop-Service -Name {name} -ErrorAction Stop
  $service.WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Stopped,
    [TimeSpan]::FromSeconds(30)
  )
}}
$service.Refresh()
[pscustomobject]@{{ stopped = [bool]($service.Status -eq 'Stopped') }}
""".strip(),
        timeout_seconds=45,
    )
    if not bool(result.get("stopped", False)):
        raise RuntimeError("HMS Agent service did not stop cleanly")


def _start_service(service_name: str) -> None:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction Stop
if ($service.Status -ne 'Running') {{
  Start-Service -Name {name} -ErrorAction Stop
  $service.WaitForStatus(
    [System.ServiceProcess.ServiceControllerStatus]::Running,
    [TimeSpan]::FromSeconds(30)
  )
}}
$service.Refresh()
[pscustomobject]@{{ running = [bool]($service.Status -eq 'Running') }}
""".strip(),
        timeout_seconds=45,
    )
    if not bool(result.get("running", False)):
        raise RuntimeError("HMS Agent service did not restart cleanly")


def _delete_service_if_present(service_name: str) -> None:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction SilentlyContinue
if ($null -ne $service) {{
  if ($service.Status -ne 'Stopped') {{
    Stop-Service -Name {name} -ErrorAction Stop
    $service.WaitForStatus(
      [System.ServiceProcess.ServiceControllerStatus]::Stopped,
      [TimeSpan]::FromSeconds(30)
    )
  }}
  & sc.exe delete {name} | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'sc.exe delete HMS Agent failed' }}
}}
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {{
  $remaining = Get-Service -Name {name} -ErrorAction SilentlyContinue
  if ($null -eq $remaining) {{ break }}
  Start-Sleep -Milliseconds 200
}} while ([DateTime]::UtcNow -lt $deadline)
[pscustomobject]@{{ deleted = [bool]($null -eq (Get-Service -Name {name} -ErrorAction SilentlyContinue)) }}
""".strip(),
        timeout_seconds=60,
    )
    if not bool(result.get("deleted", False)):
        raise RuntimeError("HMS Agent service cleanup did not complete")


def _cleanup_owned_paths(
    service: AgentServiceConfig,
    *,
    ownership_token: str,
) -> None:
    _delete_service_if_present(service.service_name)
    runtime_root = Path(service.runtime_path)
    marker = Path(service.binary_path).parent / _MARKER_FILENAME
    if runtime_root.exists():
        if not marker.is_file() or marker.read_text(encoding="utf-8") != ownership_token:
            raise PermissionError("refusing to remove unowned HMS native qualification paths")
        shutil.rmtree(runtime_root)
    workspace = Path(service.workspace_path)
    if workspace.exists():
        shutil.rmtree(workspace)


def _write_result(path: Path, result: dict[str, object]) -> None:
    data = json.dumps(
        result,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ) + "\n"
    path.write_text(data, encoding="utf-8")


def qualify(package_dir: Path, result_path: Path) -> dict[str, object]:
    _require_github_hosted_windows_admin()
    service = AgentServiceConfig()
    service.validate()

    source_executable = (package_dir / "hms-agent.exe").resolve(strict=True)
    source_manifest_path = (package_dir / "hms-agent.manifest.json").resolve(strict=True)
    manifest: AgentPackageManifest = load_agent_package_manifest(source_manifest_path)
    verify_agent_package(source_executable, manifest)
    require_windows_amd64_pe(source_executable)

    runtime_root = Path(service.runtime_path)
    workspace_root = Path(service.workspace_path)
    if _service_exists(service.service_name):
        raise RuntimeError("HMSAgent service already exists on qualification runner")
    if runtime_root.exists() or workspace_root.exists():
        raise RuntimeError("managed HMS qualification paths already exist on runner")

    ownership_token = secrets.token_hex(24)
    agent_root = Path(service.binary_path).parent
    state_root = Path(service.state_path)
    agent_root.mkdir(parents=True)
    marker = agent_root / _MARKER_FILENAME
    marker.write_text(ownership_token, encoding="utf-8")
    state_root.mkdir(parents=True)
    workspace_root.mkdir(parents=True)

    target_executable = Path(service.binary_path)
    shutil.copy2(source_executable, target_executable)
    verify_agent_package(target_executable, manifest)
    require_windows_amd64_pe(target_executable)

    credential = AgentDeviceCredential(
        instance_id=_INSTANCE_ID,
        device_id=_DEVICE_ID,
        secret=secrets.token_bytes(AGENT_DEVICE_SECRET_BYTES),
    )
    GuestAgentDeviceCredentialStore(
        guest_device_credential_path(state_root)
    ).save_create_only(credential)

    runtime = AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id=_INSTANCE_ID,
        project_id=_PROJECT_ID,
        bridge_origin=_BRIDGE_ORIGIN,
        workspace_root=service.workspace_path,
        state_root=service.state_path,
        python_executable=str(Path(sys.executable).resolve(strict=True)),
        git_executable=_find_git_executable(),
        health_port=_HEALTH_PORT,
    )
    runtime.validate()

    result: dict[str, object] = {}
    try:
        install_result = run_powershell_json(
            build_agent_service_install_script(
                service,
                expected_sha256=manifest.sha256,
                runtime_config=runtime,
            ),
            timeout_seconds=180,
        )
        if not bool(install_result.get("ready", False)):
            raise RuntimeError("native HMS Agent installer did not prove service Running")

        readiness = run_powershell_json(
            build_agent_service_readiness_script(
                service,
                expected_sha256=manifest.sha256,
                runtime_config=runtime,
            ),
            timeout_seconds=90,
        )
        if not bool(readiness.get("service_ready", False)):
            raise RuntimeError("native HMS Agent service readiness contract failed")

        first_health = _wait_for_health(manifest.version)
        first_listener = _probe_listener(service.service_name)
        first_epoch = _wait_for_epoch(state_root, minimum_epoch=1)
        reconnect_epoch = _wait_for_epoch(
            state_root,
            minimum_epoch=first_epoch + 1,
            timeout_seconds=10.0,
        )

        _stop_service(service.service_name)
        _require_health_unreachable()
        _start_service(service.service_name)

        second_health = _wait_for_health(manifest.version)
        second_listener = _probe_listener(service.service_name)
        if second_health.boot_id == first_health.boot_id:
            raise RuntimeError("Agent boot_id did not change across SCM restart")
        post_restart_epoch = _wait_for_epoch(
            state_root,
            minimum_epoch=reconnect_epoch + 1,
            timeout_seconds=10.0,
        )

        result = {
            "schema_version": 1,
            "qualification": "native_windows_scm_packaged_agent",
            "package": manifest.to_dict(),
            "install": {
                "ready": bool(install_result.get("ready", False)),
                "start_name": str(install_result.get("start_name", "")),
                "service_sid_type": str(install_result.get("service_sid_type", "")),
                "binary_sha256": str(install_result.get("binary_sha256", "")),
                "runtime_config_sha256": str(
                    install_result.get("runtime_config_sha256", "")
                ),
            },
            "readiness": {
                "service_ready": bool(readiness.get("service_ready", False)),
                "local_service_account": bool(
                    readiness.get("local_service_account", False)
                ),
                "service_sid_unrestricted": bool(
                    readiness.get("service_sid_unrestricted", False)
                ),
                "runtime_config_sha256_ok": bool(
                    readiness.get("runtime_config_sha256_ok", False)
                ),
            },
            "first_health": {
                "instance_id": first_health.instance_id,
                "agent_version": first_health.agent_version,
                "service_identity": first_health.service_identity,
                "privilege": first_health.privilege,
                "listener_scope": first_health.listener_scope,
                "boot_id": first_health.boot_id,
            },
            "first_listener": first_listener,
            "first_epoch": first_epoch,
            "reconnect_epoch": reconnect_epoch,
            "second_health": {
                "boot_id": second_health.boot_id,
                "service_identity": second_health.service_identity,
                "privilege": second_health.privilege,
                "listener_scope": second_health.listener_scope,
            },
            "second_listener": second_listener,
            "post_restart_epoch": post_restart_epoch,
            "transport_target": "loopback-closed-port-retry-only",
            "full_bridge_command_flow_proven": False,
            "hyperv_guest_proven": False,
        }
    finally:
        _cleanup_owned_paths(service, ownership_token=ownership_token)

    result["cleanup_verified"] = True
    _write_result(result_path, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify the packaged HMS Agent as a native Windows SCM service"
    )
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("result", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    result = qualify(args.package_dir.resolve(), args.result.resolve())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
