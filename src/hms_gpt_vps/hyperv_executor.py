from __future__ import annotations

from dataclasses import dataclass

from .hyperv_vm import build_reconcile_vm_script, reconcile_vm
from .windows_provisioner import WindowsVMConfig


@dataclass(frozen=True)
class HyperVExecutionResult:
    changed: bool
    stdout: str


def build_ensure_vm_script(config: WindowsVMConfig) -> str:
    """Compatibility wrapper for the hardened VM reconciler."""
    return build_reconcile_vm_script(config)


def ensure_vm(config: WindowsVMConfig) -> HyperVExecutionResult:
    """Compatibility wrapper preserving the R002A public result shape."""
    result = reconcile_vm(config)
    return HyperVExecutionResult(
        changed=bool(result.get("changed", False)),
        stdout=str(result),
    )
