from __future__ import annotations

from .agent_service_install import AgentServiceConfig
from .powershell import ps_literal
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json_by_id


class ManagedGuestListenerProofError(RuntimeError):
    pass


def probe_managed_agent_health_listener_by_id(
    vm_id: str,
    vm_name: str,
    credential: PowerShellDirectCredential,
    service: AgentServiceConfig,
    health_port: int,
    *,
    timeout_seconds: int = 30,
) -> dict[str, object]:
    """Prove the Agent health listener from guest OS socket state.

    The guest call is bound to the already-persisted Hyper-V VMId by
    ``run_vm_powershell_json_by_id``. The proof does not trust `/healthz`'s
    self-reported listener scope: it resolves the SCM process id and requires
    exactly one listening TCP socket for that process/port, bound only to IPv4
    loopback.
    """

    credential.validate()
    service.validate()
    if not isinstance(health_port, int) or isinstance(health_port, bool):
        raise TypeError("health_port must be an integer")
    if health_port < 1 or health_port > 65535:
        raise ValueError("health_port must be between 1 and 65535")

    script = f"""
$ErrorActionPreference = 'Stop'
$serviceName = {ps_literal(service.service_name)}
$healthPort = [int]{health_port}
$filter = "Name='" + $serviceName + "'"
$service = Get-CimInstance Win32_Service -Filter $filter -ErrorAction Stop
$pidValue = [int]$service.ProcessId
if ($pidValue -le 0) {{
  throw 'HMS Agent service has no live process id'
}}
$connections = @(
  Get-NetTCPConnection -State Listen -LocalPort $healthPort -ErrorAction Stop |
    Where-Object {{ [int]$_.OwningProcess -eq $pidValue }}
)
[pscustomobject]@{{
  service_name = [string]$service.Name
  process_id = $pidValue
  health_port = $healthPort
  listener_count = [int]$connections.Count
  local_addresses = @($connections | ForEach-Object {{ [string]$_.LocalAddress }})
}}
""".strip()

    result = run_vm_powershell_json_by_id(
        vm_id,
        vm_name,
        credential,
        script,
        timeout_seconds=timeout_seconds,
    )

    expected_keys = {
        "service_name",
        "process_id",
        "health_port",
        "listener_count",
        "local_addresses",
    }
    if set(result) != expected_keys:
        raise ManagedGuestListenerProofError(
            "managed guest listener proof fields do not match schema"
        )
    if result.get("service_name") != service.service_name:
        raise ManagedGuestListenerProofError(
            "managed guest listener proof returned the wrong service identity"
        )
    process_id = result.get("process_id")
    if (
        not isinstance(process_id, int)
        or isinstance(process_id, bool)
        or process_id <= 0
    ):
        raise ManagedGuestListenerProofError(
            "managed guest listener proof returned an invalid service process id"
        )
    observed_port = result.get("health_port")
    if (
        not isinstance(observed_port, int)
        or isinstance(observed_port, bool)
        or observed_port != health_port
    ):
        raise ManagedGuestListenerProofError(
            "managed guest listener proof returned the wrong health port"
        )
    listener_count = result.get("listener_count")
    if (
        not isinstance(listener_count, int)
        or isinstance(listener_count, bool)
        or listener_count != 1
    ):
        raise ManagedGuestListenerProofError(
            "managed guest Agent health must have exactly one listening socket"
        )

    addresses_raw = result.get("local_addresses")
    if not isinstance(addresses_raw, list) or not all(
        isinstance(value, str) for value in addresses_raw
    ):
        raise ManagedGuestListenerProofError(
            "managed guest listener address evidence has invalid shape"
        )
    addresses = list(addresses_raw)
    if addresses != ["127.0.0.1"]:
        raise ManagedGuestListenerProofError(
            "managed guest Agent health listener is not bound exclusively to IPv4 loopback"
        )

    return {
        "os_listener_proven": True,
        "service_name": service.service_name,
        "process_id": process_id,
        "health_port": health_port,
        "listener_count": 1,
        "local_addresses": addresses,
        "vm_id": vm_id.lower(),
    }
