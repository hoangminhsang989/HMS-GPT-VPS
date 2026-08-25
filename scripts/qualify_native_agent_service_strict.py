from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

import qualify_native_agent_service as legacy

from hms_gpt_vps.agent_device_credential_store import (
    GuestAgentDeviceCredentialStore,
    guest_device_credential_path,
)
from hms_gpt_vps.agent_package import (
    AgentPackageManifest,
    load_agent_package_manifest,
    require_windows_amd64_pe,
    verify_agent_package,
)
from hms_gpt_vps.agent_package_manifest_artifact import (
    canonical_agent_package_manifest_bytes,
    managed_agent_package_manifest_path,
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
from hms_gpt_vps.native_scm_qualification_evidence import (
    validate_install_result,
    validate_listener_result,
    validate_native_scm_proof,
    validate_readiness_result,
    validate_service_exists_result,
    validate_single_true_result,
)
from hms_gpt_vps.powershell import ps_literal, run_powershell_json


_RESULT_MAX_BYTES = 1024 * 1024


def _service_exists(service_name: str) -> bool:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction SilentlyContinue
$exists = $null -ne $service
if ($null -ne $service) {{ $service.Dispose() }}
[pscustomobject]@{{ exists = [bool]$exists }}
""".strip(),
        timeout_seconds=30,
    )
    return validate_service_exists_result(result)


def _probe_listener(service_name: str) -> dict[str, object]:
    name = ps_literal(service_name)
    escaped_name = service_name.replace("'", "''")
    result = run_powershell_json(
        f"""
$service = Get-CimInstance Win32_Service -Filter "Name='{escaped_name}'" -ErrorAction Stop
$pidValue = [int]$service.ProcessId
if ($pidValue -le 0) {{ throw 'HMS Agent service has no live process id' }}
$connections = @(
  Get-NetTCPConnection -State Listen -LocalPort {legacy._HEALTH_PORT} -ErrorAction Stop |
    Where-Object {{ [int]$_.OwningProcess -eq $pidValue }}
)
[pscustomobject]@{{
  service_name = {name}
  process_id = $pidValue
  listener_count = [int]$connections.Count
  local_addresses = @($connections | ForEach-Object {{ [string]$_.LocalAddress }})
}}
""".strip(),
        timeout_seconds=30,
    )
    return validate_listener_result(result, service_name=service_name)


def _stop_service(service_name: str) -> None:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction Stop
try {{
  if ($service.Status -ne 'Stopped') {{
    $null = Stop-Service -Name {name} -ErrorAction Stop -WarningAction SilentlyContinue
    $null = $service.WaitForStatus(
      [System.ServiceProcess.ServiceControllerStatus]::Stopped,
      [TimeSpan]::FromSeconds(30)
    )
  }}
  $null = $service.Refresh()
  $stopped = $service.Status -eq 'Stopped'
}} finally {{
  $null = $service.Dispose()
}}
[pscustomobject]@{{ stopped = [bool]$stopped }}
""".strip(),
        timeout_seconds=45,
    )
    validate_single_true_result(result, "stopped", "native service-stop evidence")


def _start_service(service_name: str) -> None:
    name = ps_literal(service_name)
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction Stop
try {{
  if ($service.Status -ne 'Running') {{
    $null = Start-Service -Name {name} -ErrorAction Stop -WarningAction SilentlyContinue
    $null = $service.WaitForStatus(
      [System.ServiceProcess.ServiceControllerStatus]::Running,
      [TimeSpan]::FromSeconds(30)
    )
  }}
  $null = $service.Refresh()
  $running = $service.Status -eq 'Running'
}} finally {{
  $null = $service.Dispose()
}}
[pscustomobject]@{{ running = [bool]$running }}
""".strip(),
        timeout_seconds=45,
    )
    validate_single_true_result(result, "running", "native service-start evidence")


def _delete_service_if_present(service_name: str) -> None:
    name = ps_literal(service_name)
    escaped_name = service_name.replace("'", "''")
    result = run_powershell_json(
        f"""
$service = Get-Service -Name {name} -ErrorAction SilentlyContinue
if ($null -ne $service) {{
  try {{
    if ($service.Status -ne 'Stopped') {{
      $null = Stop-Service -Name {name} -ErrorAction Stop -WarningAction SilentlyContinue
      $null = $service.WaitForStatus(
        [System.ServiceProcess.ServiceControllerStatus]::Stopped,
        [TimeSpan]::FromSeconds(30)
      )
    }}
  }} finally {{
    $null = $service.Dispose()
    $service = $null
  }}
  & sc.exe delete {name} | Out-Null
  if ($LASTEXITCODE -ne 0) {{ throw 'sc.exe delete HMS Agent failed' }}
  [GC]::Collect()
  [GC]::WaitForPendingFinalizers()
}}
$deadline = [DateTime]::UtcNow.AddSeconds(15)
do {{
  $remaining = Get-CimInstance Win32_Service -Filter "Name='{escaped_name}'" -ErrorAction SilentlyContinue
  if ($null -eq $remaining) {{ break }}
  Start-Sleep -Milliseconds 200
}} while ([DateTime]::UtcNow -lt $deadline)
[pscustomobject]@{{
  deleted = [bool]($null -eq (Get-CimInstance Win32_Service -Filter "Name='{escaped_name}'" -ErrorAction SilentlyContinue))
}}
""".strip(),
        timeout_seconds=60,
    )
    validate_single_true_result(result, "deleted", "native service-delete evidence")


def _cleanup_owned_paths(service: AgentServiceConfig, *, ownership_token: str) -> None:
    _delete_service_if_present(service.service_name)
    runtime_root = Path(service.runtime_path)
    runtime_marker = runtime_root / legacy._MARKER_FILENAME
    if runtime_root.exists():
        legacy._require_owned_marker(runtime_marker, ownership_token, "runtime")
        shutil.rmtree(runtime_root)
    workspace = Path(service.workspace_path)
    workspace_marker = workspace / legacy._WORKSPACE_MARKER_FILENAME
    if workspace.exists():
        legacy._require_owned_marker(workspace_marker, ownership_token, "workspace")
        shutil.rmtree(workspace)


def _write_result_create_only(path: Path, result: dict[str, object]) -> None:
    data = (
        json.dumps(
            result,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(data) > _RESULT_MAX_BYTES:
        raise RuntimeError("native SCM proof exceeds publication bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.read_bytes() != data:
            raise RuntimeError("native SCM proof readback mismatch")
    finally:
        os.close(fd)


def qualify(package_dir: Path, result_path: Path) -> dict[str, object]:
    legacy._require_github_hosted_windows_admin()
    service = AgentServiceConfig()
    service.validate()

    source_package = package_dir / "hms-agent"
    source_manifest_path = (package_dir / "hms-agent.manifest.json").resolve(strict=True)
    manifest: AgentPackageManifest = load_agent_package_manifest(source_manifest_path)
    canonical_manifest = canonical_agent_package_manifest_bytes(manifest)
    if source_manifest_path.read_bytes() != canonical_manifest:
        raise ValueError("native qualification source manifest is not canonical")
    verify_agent_package(source_package, manifest)
    require_windows_amd64_pe(source_package / manifest.entrypoint)

    runtime_root = Path(service.runtime_path)
    workspace_root = Path(service.workspace_path)
    if _service_exists(service.service_name):
        raise RuntimeError("HMSAgent service already exists on qualification runner")
    if runtime_root.exists() or workspace_root.exists():
        raise RuntimeError("managed HMS qualification paths already exist on runner")
    if result_path.exists():
        raise FileExistsError("native SCM proof target already exists")

    ownership_token = secrets.token_hex(24)
    agent_root = Path(service.agent_root_path)
    target_package = Path(service.package_path)
    target_manifest = Path(managed_agent_package_manifest_path(service.agent_root_path))
    state_root = Path(service.state_path)
    runtime_root.mkdir(parents=True)
    (runtime_root / legacy._MARKER_FILENAME).write_text(ownership_token, encoding="utf-8")
    agent_root.mkdir(parents=True)
    state_root.mkdir(parents=True)
    workspace_root.mkdir(parents=True)
    (workspace_root / legacy._WORKSPACE_MARKER_FILENAME).write_text(
        ownership_token, encoding="utf-8"
    )

    shutil.copytree(source_package, target_package)
    target_manifest.write_bytes(canonical_manifest)
    if target_manifest.read_bytes() != canonical_manifest:
        raise RuntimeError("native qualification canonical manifest publication failed")
    if load_agent_package_manifest(target_manifest) != manifest:
        raise RuntimeError("native qualification published manifest identity mismatch")
    verify_agent_package(target_package, manifest)
    require_windows_amd64_pe(Path(service.binary_path))

    credential = AgentDeviceCredential(
        instance_id=legacy._INSTANCE_ID,
        device_id=legacy._DEVICE_ID,
        secret=secrets.token_bytes(AGENT_DEVICE_SECRET_BYTES),
    )
    GuestAgentDeviceCredentialStore(guest_device_credential_path(state_root)).save_create_only(
        credential
    )

    runtime = AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id=legacy._INSTANCE_ID,
        project_id=legacy._PROJECT_ID,
        bridge_origin=legacy._BRIDGE_ORIGIN,
        workspace_root=service.workspace_path,
        state_root=service.state_path,
        python_executable=str(Path(sys.executable).resolve(strict=True)),
        git_executable=legacy._find_git_executable(),
        health_port=legacy._HEALTH_PORT,
    )
    runtime.validate()

    result: dict[str, object] = {}
    try:
        install_result = validate_install_result(
            run_powershell_json(
                build_agent_service_install_script(
                    service,
                    package_manifest=manifest,
                    runtime_config=runtime,
                ),
                timeout_seconds=180,
            ),
            service=service,
            manifest=manifest,
            runtime=runtime,
        )
        readiness = validate_readiness_result(
            run_powershell_json(
                build_agent_service_readiness_script(
                    service,
                    package_manifest=manifest,
                    runtime_config=runtime,
                ),
                timeout_seconds=90,
            ),
            manifest=manifest,
            runtime=runtime,
        )

        first_health = legacy._wait_for_health(manifest.version)
        first_listener = _probe_listener(service.service_name)
        first_epoch = legacy._wait_for_epoch(state_root, minimum_epoch=1)
        reconnect_epoch = legacy._wait_for_epoch(
            state_root,
            minimum_epoch=first_epoch + 1,
            timeout_seconds=10.0,
        )

        _stop_service(service.service_name)
        legacy._require_health_unreachable()
        _start_service(service.service_name)

        second_health = legacy._wait_for_health(manifest.version)
        second_listener = _probe_listener(service.service_name)
        if second_health.boot_id == first_health.boot_id:
            raise RuntimeError("Agent boot_id did not change across SCM restart")
        post_restart_epoch = legacy._wait_for_epoch(
            state_root,
            minimum_epoch=reconnect_epoch + 1,
            timeout_seconds=10.0,
        )

        verify_agent_package(target_package, manifest)
        if target_manifest.read_bytes() != canonical_manifest:
            raise RuntimeError("canonical Agent manifest changed during native qualification")
        result = {
            "schema_version": 1,
            "qualification": "native_windows_scm_packaged_agent",
            "package": legacy._package_proof_summary(manifest),
            "install": {
                "ready": install_result["ready"],
                "start_name": install_result["start_name"],
                "service_sid_type": install_result["service_sid_type"],
                "package_file_count": install_result["package_file_count"],
                "package_total_size": install_result["package_total_size"],
                "binary_sha256": install_result["binary_sha256"],
                "runtime_config_sha256": install_result["runtime_config_sha256"],
            },
            "readiness": {
                "service_ready": readiness["service_ready"],
                "local_service_account": readiness["local_service_account"],
                "service_sid_unrestricted": readiness["service_sid_unrestricted"],
                "package_tree_ok": readiness["package_tree_ok"],
                "package_file_count": readiness["package_file_count"],
                "package_total_size": readiness["package_total_size"],
                "runtime_config_sha256_ok": readiness["runtime_config_sha256_ok"],
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
    except BaseException as exc:
        legacy._print_failure_evidence(service.service_name, exc)
        try:
            _cleanup_owned_paths(service, ownership_token=ownership_token)
        except Exception as cleanup_exc:
            print(
                json.dumps(
                    {"cleanup_failure": type(cleanup_exc).__name__},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                file=sys.stderr,
            )
        raise

    _cleanup_owned_paths(service, ownership_token=ownership_token)
    result["cleanup_verified"] = True
    validate_native_scm_proof(result)
    _write_result_create_only(result_path, result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Strictly qualify the packaged HMS Agent as a native Windows SCM service"
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
