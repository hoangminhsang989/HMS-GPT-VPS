from __future__ import annotations

import base64
import json
from pathlib import Path
import uuid

from .agent_device_credential_store import GUEST_PROTECTION_SCOPE
from .agent_device_enrollment import AgentDeviceEnrollmentConfig
from .agent_device_enrollment_probe import (
    AgentDeviceEnrollmentProbeError,
    build_agent_device_enrollment_probe_script,
)
from .agent_health_contract import DEFAULT_REQUIRED_CAPABILITIES, AgentHealthExpectation
from .agent_health_probe import (
    AgentHealthProbeConfig,
    build_agent_health_probe_script,
    validate_agent_application_health_evidence,
)
from .agent_package_manifest_artifact import canonical_agent_package_manifest_sha256
from .agent_package_transfer import (
    AgentPackageTransferPlan,
    build_prepare_agent_package_staging_script,
    build_publish_agent_package_script,
)
from .agent_package_transfer_recovery import (
    build_agent_package_ready_probe_script,
    build_reset_owned_agent_package_staging_script,
)
from .agent_post_install_observe import AgentPostInstallObservation
from .agent_service_install import AgentServiceConfig, build_agent_service_install_script
from .agent_service_readiness import build_agent_service_readiness_script
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .agent_transport_protocol import AgentDeviceCredential
from .powershell import ps_literal, run_powershell_json
from .powershell_direct import (
    PowerShellDirectCredential,
    run_vm_powershell_json_by_id,
)
from .powershell_sha256 import POWERSHELL_SHA256_FUNCTION


_GUEST_SERVICE_INTERFACE_NAME = "Guest Service Interface"
_MAX_HOST_COPY_SCRIPT_BYTES = 24 * 1024


def normalize_managed_vm_id(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("managed VMId is required")
    try:
        return str(uuid.UUID(value.strip())).lower()
    except (ValueError, AttributeError) as exc:
        raise ValueError("managed VMId must be a valid GUID") from exc


def _managed_vm_prelude(vm_id: str, vm_name: str) -> str:
    managed_vm_id = normalize_managed_vm_id(vm_id)
    if not isinstance(vm_name, str) or not vm_name.strip():
        raise ValueError("managed VM name is required")
    return f"""
$vmId = [guid]{ps_literal(managed_vm_id)}
$expectedVmName = {ps_literal(vm_name)}
$managedVm = Get-VM -Id $vmId -ErrorAction Stop
if ($managedVm.Name -ine $expectedVmName) {{
  throw 'Persisted Hyper-V VMId resolves to a different VM name'
}}
""".strip()


def probe_guest_service_interface_enabled_by_id(vm_id: str, vm_name: str) -> bool:
    """Read the exact managed VM Guest Service Interface baseline by VMId."""
    result = run_powershell_json(
        f"""
$ErrorActionPreference = 'Stop'
{_managed_vm_prelude(vm_id, vm_name)}
$service = Get-VMIntegrationService -VM $managedVm -Name {ps_literal(_GUEST_SERVICE_INTERFACE_NAME)} -ErrorAction Stop
[pscustomobject]@{{ enabled = [bool]$service.Enabled; vm_id = $managedVm.Id.Guid }}
""".strip(),
        timeout_seconds=30,
    )
    enabled = result.get("enabled")
    if not isinstance(enabled, bool):
        raise RuntimeError("Guest Service Interface VMId-bound baseline evidence is invalid")
    observed_vm_id = str(result.get("vm_id", "")).lower()
    if observed_vm_id != normalize_managed_vm_id(vm_id):
        raise RuntimeError("Guest Service Interface baseline returned wrong VMId")
    return enabled


def restore_guest_service_interface_state_by_id(
    vm_id: str,
    vm_name: str,
    expected_enabled: bool,
) -> dict[str, object]:
    """Restore the exact managed VM integration-service state by VM object."""
    if not isinstance(expected_enabled, bool):
        raise TypeError("expected Guest Service Interface state must be boolean")
    expected = "$true" if expected_enabled else "$false"
    result = run_powershell_json(
        f"""
$ErrorActionPreference = 'Stop'
{_managed_vm_prelude(vm_id, vm_name)}
$integrationName = {ps_literal(_GUEST_SERVICE_INTERFACE_NAME)}
$expectedEnabled = {expected}
$service = Get-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction Stop
$changed = $false
if ([bool]$service.Enabled -ne $expectedEnabled) {{
  if ($expectedEnabled) {{
    Enable-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction Stop | Out-Null
  }} else {{
    Disable-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction Stop | Out-Null
  }}
  $changed = $true
}}
$verified = Get-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction Stop
[pscustomobject]@{{
  restored = [bool]([bool]$verified.Enabled -eq $expectedEnabled)
  enabled = [bool]$verified.Enabled
  changed = [bool]$changed
  vm_id = $managedVm.Id.Guid
}}
""".strip(),
        timeout_seconds=30,
    )
    if not bool(result.get("restored", False)):
        raise RuntimeError("Guest Service Interface VMId-bound restoration failed")
    if result.get("enabled") is not expected_enabled:
        raise RuntimeError("Guest Service Interface readback differs from persisted baseline")
    if str(result.get("vm_id", "")).lower() != normalize_managed_vm_id(vm_id):
        raise RuntimeError("Guest Service Interface restoration returned wrong VMId")
    return result


def _copy_entries_payload(plan: AgentPackageTransferPlan) -> str:
    plan.validate()
    payload = [
        [item.path, item.size, item.sha256.lower()]
        for item in plan.manifest.files
    ]
    raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def build_copy_agent_package_to_staging_by_id_script(
    vm_id: str,
    vm_name: str,
    plan: AgentPackageTransferPlan,
) -> str:
    """Build a bounded Copy-VMFile window locked to one exact Hyper-V VM object."""
    plan.validate()
    source_root = plan.source_root.resolve(strict=True)
    manifest_source = plan.manifest_source.resolve(strict=True)
    entries_payload = _copy_entries_payload(plan)
    script = f"""
$ErrorActionPreference = 'Stop'
{_managed_vm_prelude(vm_id, vm_name)}
$sourceRoot = {ps_literal(source_root)}
$stagingRoot = {ps_literal(plan.layout.staging_package_root)}
$manifestSource = {ps_literal(manifest_source)}
$manifestDestination = {ps_literal(plan.layout.staging_manifest_path)}
$expectedManifestHash = {ps_literal(plan.manifest_sha256)}
$expectedManifestSize = [int64]{plan.manifest_size}
$entriesPayload = {ps_literal(entries_payload)}
$integrationName = {ps_literal(_GUEST_SERVICE_INTERFACE_NAME)}

{POWERSHELL_SHA256_FUNCTION}

$entriesJson = [System.Text.Encoding]::UTF8.GetString(
  [Convert]::FromBase64String($entriesPayload)
)
$entries = @($entriesJson | ConvertFrom-Json -ErrorAction Stop)
if ($entries.Count -ne {plan.manifest.file_count}) {{
  throw 'HMS Agent VMId-bound host copy plan file count mismatch'
}}
if (-not (Test-Path -LiteralPath $manifestSource -PathType Leaf)) {{
  throw 'HMS Agent manifest source disappeared before VMId-bound copy'
}}
$manifestItem = Get-Item -LiteralPath $manifestSource -Force -ErrorAction Stop
if (($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
  throw 'HMS Agent manifest source became a reparse point'
}}
if ([int64]$manifestItem.Length -ne $expectedManifestSize) {{
  throw 'HMS Agent manifest source size changed before VMId-bound copy'
}}
if ((Get-HmsSha256 $manifestSource) -ne $expectedManifestHash) {{
  throw 'HMS Agent manifest source hash changed before VMId-bound copy'
}}

$service = Get-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction Stop
$wasEnabled = [bool]$service.Enabled
$enabledTemporarily = $false
[int]$copiedFiles = 0
try {{
  if (-not $wasEnabled) {{
    Enable-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction Stop | Out-Null
    $enabledTemporarily = $true
  }}
  foreach ($entry in $entries) {{
    $relative = [string]$entry[0]
    $expectedSize = [int64]$entry[1]
    $expectedHash = ([string]$entry[2]).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('\\') -or $relative.StartsWith('/') -or $relative.Contains('../') -or $relative.Contains('/../') -or $relative.EndsWith('/..')) {{
      throw 'HMS Agent VMId-bound copy plan contains an unsafe relative path'
    }}
    $windowsRelative = $relative.Replace('/', '\\')
    $source = [System.IO.Path]::Combine($sourceRoot, $windowsRelative)
    $destination = [System.IO.Path]::Combine($stagingRoot, $windowsRelative)
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {{
      throw 'HMS Agent package source file disappeared before VMId-bound copy'
    }}
    $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if (($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {{
      throw 'HMS Agent package source file became a reparse point'
    }}
    if ([int64]$sourceItem.Length -ne $expectedSize) {{
      throw 'HMS Agent package source file size changed before VMId-bound copy'
    }}
    if ((Get-HmsSha256 $source) -ne $expectedHash) {{
      throw 'HMS Agent package source file hash changed before VMId-bound copy'
    }}
    Copy-VMFile -VM $managedVm -SourcePath $source -DestinationPath $destination -FileSource Host -CreateFullPath -ErrorAction Stop | Out-Null
    $copiedFiles += 1
  }}
  Copy-VMFile -VM $managedVm -SourcePath $manifestSource -DestinationPath $manifestDestination -FileSource Host -CreateFullPath -ErrorAction Stop | Out-Null
  [pscustomobject]@{{
    copied = $true
    copied_files = $copiedFiles
    manifest_copied = $true
    enabled_temporarily = $enabledTemporarily
    staging_root = $stagingRoot
    vm_id = $managedVm.Id.Guid
  }}
}} finally {{
  if ($enabledTemporarily) {{
    Disable-VMIntegrationService -VM $managedVm -Name $integrationName -ErrorAction SilentlyContinue | Out-Null
  }}
}}
""".strip()
    if len(script.encode("utf-8")) > _MAX_HOST_COPY_SCRIPT_BYTES:
        raise ValueError(
            "Agent VMId-bound package copy plan exceeds bounded host PowerShell command size"
        )
    return script


def reset_owned_agent_package_staging_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    plan: AgentPackageTransferPlan,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    result = run_vm_powershell_json_by_id(
        vm_id,
        vm_name,
        credential,
        build_reset_owned_agent_package_staging_script(plan),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("reset", False)):
        raise RuntimeError("owned Agent package staging reset postcondition failed")
    return result


def transfer_agent_package_to_guest_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    plan: AgentPackageTransferPlan,
    *,
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Stage/copy/publish one package while all VM targeting is GUID-bound."""
    managed_vm_id = normalize_managed_vm_id(vm_id)
    plan.validate()
    prepared = run_vm_powershell_json_by_id(
        managed_vm_id,
        vm_name,
        credential,
        build_prepare_agent_package_staging_script(plan),
        timeout_seconds=60,
    )
    if not bool(prepared.get("staging_ready", False)):
        raise RuntimeError("HMS Agent VMId-bound package staging preparation failed")

    copied = run_powershell_json(
        build_copy_agent_package_to_staging_by_id_script(managed_vm_id, vm_name, plan),
        timeout_seconds=timeout_seconds,
    )
    if not bool(copied.get("copied", False)):
        raise RuntimeError("HMS Agent VMId-bound Copy-VMFile transfer failed")
    if str(copied.get("vm_id", "")).lower() != managed_vm_id:
        raise RuntimeError("HMS Agent VMId-bound copy returned wrong VMId")
    if int(copied.get("copied_files", 0)) != plan.manifest.file_count:
        raise RuntimeError("HMS Agent VMId-bound Copy-VMFile count postcondition failed")
    if not bool(copied.get("manifest_copied", False)):
        raise RuntimeError("HMS Agent VMId-bound manifest copy postcondition failed")

    published = run_vm_powershell_json_by_id(
        managed_vm_id,
        vm_name,
        credential,
        build_publish_agent_package_script(plan),
        timeout_seconds=timeout_seconds,
    )
    if not bool(published.get("published", False)):
        raise RuntimeError("HMS Agent VMId-bound guest publication failed")
    if int(published.get("file_count", 0)) != plan.manifest.file_count:
        raise RuntimeError("HMS Agent final package file-count postcondition failed")
    if int(published.get("total_size", 0)) != plan.manifest.total_size:
        raise RuntimeError("HMS Agent final package size postcondition failed")
    if str(published.get("entrypoint_sha256", "")).lower() != plan.manifest.sha256.lower():
        raise RuntimeError("HMS Agent final package entrypoint postcondition failed")
    if str(published.get("manifest_sha256", "")).lower() != plan.manifest_sha256:
        raise RuntimeError("HMS Agent final manifest postcondition failed")
    if not bool(published.get("staging_removed", False)):
        raise RuntimeError("HMS Agent package staging cleanup postcondition failed")

    return {
        "staging_prepared": True,
        "copied_files": plan.manifest.file_count,
        "manifest_copied": True,
        "published": True,
        "already_published": bool(published.get("already_published", False)),
        "file_count": plan.manifest.file_count,
        "total_size": plan.manifest.total_size,
        "entrypoint_sha256": plan.manifest.sha256.lower(),
        "manifest_sha256": plan.manifest_sha256,
        "final_package_root": plan.layout.final_package_root,
        "final_manifest_path": plan.layout.final_manifest_path,
        "staging_removed": True,
        "vm_id": managed_vm_id,
    }


def probe_agent_package_ready_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    service: AgentServiceConfig,
    manifest,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:  # type: ignore[no-untyped-def]
    result = run_vm_powershell_json_by_id(
        vm_id,
        vm_name,
        credential,
        build_agent_package_ready_probe_script(service, manifest),
        timeout_seconds=timeout_seconds,
    )
    if bool(result.get("package_ready", False)):
        if int(result.get("file_count", 0)) != manifest.file_count:
            raise RuntimeError("Agent package-ready file-count proof mismatch")
        if int(result.get("total_size", 0)) != manifest.total_size:
            raise RuntimeError("Agent package-ready total-size proof mismatch")
        if str(result.get("entrypoint_sha256", "")).lower() != manifest.sha256.lower():
            raise RuntimeError("Agent package-ready entrypoint proof mismatch")
    return result


def install_agent_service_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    config: AgentServiceConfig,
    *,
    package_manifest,
    runtime_config: AgentServiceRuntimeConfig,
    timeout_seconds: int = 180,
) -> dict[str, object]:  # type: ignore[no-untyped-def]
    result = run_vm_powershell_json_by_id(
        vm_id,
        vm_name,
        credential,
        build_agent_service_install_script(
            config,
            package_manifest=package_manifest,
            runtime_config=runtime_config,
        ),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("ready", False)):
        raise RuntimeError("HMS Agent service postcondition failed")
    if str(result.get("package_manifest_sha256", "")).lower() != canonical_agent_package_manifest_sha256(package_manifest):
        raise RuntimeError("HMS Agent package manifest postcondition failed")
    if str(result.get("runtime_config_sha256", "")).lower() != runtime_config.sha256():
        raise RuntimeError("HMS Agent runtime config postcondition failed")
    if int(result.get("package_file_count", 0)) != package_manifest.file_count:
        raise RuntimeError("HMS Agent package file-count postcondition failed")
    if int(result.get("package_total_size", 0)) != package_manifest.total_size:
        raise RuntimeError("HMS Agent package size postcondition failed")
    if str(result.get("binary_sha256", "")).lower() != package_manifest.sha256.lower():
        raise RuntimeError("HMS Agent entrypoint postcondition failed")
    return result


def observe_agent_post_install_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    *,
    package_manifest,
    expected_agent_version: str,
    service: AgentServiceConfig,
    runtime: AgentServiceRuntimeConfig,
) -> AgentPostInstallObservation:  # type: ignore[no-untyped-def]
    service_evidence = run_vm_powershell_json_by_id(
        vm_id,
        vm_name,
        credential,
        build_agent_service_readiness_script(
            service,
            package_manifest=package_manifest,
            runtime_config=runtime,
        ),
        timeout_seconds=90,
    )
    if not bool(service_evidence.get("service_ready", False)):
        return AgentPostInstallObservation(
            service_evidence=service_evidence,
            health=None,
            health_error="service_not_ready",
        )

    try:
        probe_config = AgentHealthProbeConfig(
            port=runtime.health_port,
            timeout_seconds=5,
        )
        expectation = AgentHealthExpectation(
            instance_id=runtime.instance_id,
            workspace_root=runtime.workspace_root,
            required_capabilities=DEFAULT_REQUIRED_CAPABILITIES,
        )
        health_evidence = run_vm_powershell_json_by_id(
            vm_id,
            vm_name,
            credential,
            build_agent_health_probe_script(probe_config),
            timeout_seconds=probe_config.timeout_seconds + 15,
        )
        health = validate_agent_application_health_evidence(
            health_evidence,
            expectation,
            expected_agent_version=expected_agent_version,
            config=probe_config,
        )
    except Exception as exc:
        return AgentPostInstallObservation(
            service_evidence=service_evidence,
            health=None,
            health_error=type(exc).__name__,
        )

    return AgentPostInstallObservation(
        service_evidence=service_evidence,
        health=health,
        health_error=None,
    )


def probe_agent_device_enrollment_by_id(
    vm_id: str,
    vm_name: str,
    bootstrap_credential: PowerShellDirectCredential,
    config: AgentDeviceEnrollmentConfig,
    expected_credential: AgentDeviceCredential,
    *,
    timeout_seconds: int = 90,
) -> dict[str, object]:
    """Prove the exact guest device credential through VMId-bound PowerShell Direct."""
    bootstrap_credential.validate()
    result = run_vm_powershell_json_by_id(
        vm_id,
        vm_name,
        bootstrap_credential,
        build_agent_device_enrollment_probe_script(config, expected_credential),
        timeout_seconds=timeout_seconds,
    )
    if not bool(result.get("enrollment_ready", False)):
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent device enrollment is not ready"
        )
    if result.get("instance_id") != expected_credential.instance_id:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned wrong instance_id"
        )
    if result.get("device_id") != expected_credential.device_id:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned wrong device_id"
        )
    if result.get("protection_scope") != GUEST_PROTECTION_SCOPE:
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment is not LocalMachine-DPAPI protected"
        )
    credential_path = result.get("credential_path")
    if not isinstance(credential_path, str) or not credential_path.strip():
        raise AgentDeviceEnrollmentProbeError(
            "managed guest Agent enrollment returned invalid credential path"
        )
    return result
