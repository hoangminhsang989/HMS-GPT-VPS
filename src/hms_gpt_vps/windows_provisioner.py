from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ProvisionPhase(str, Enum):
    PREFLIGHT = "preflight"
    HOST_READY = "host_ready"
    IMAGE_READY = "image_ready"
    VM_CREATING = "vm_creating"
    VM_BOOTING = "vm_booting"
    GUEST_BOOTSTRAP = "guest_bootstrap"
    AGENT_READY = "agent_ready"
    PAIRING_READY = "pairing_ready"
    CONTROL_READY = "control_ready"


@dataclass(frozen=True)
class HyperVHostState:
    is_windows: bool
    hyperv_available: bool
    hyperv_enabled: bool
    virtualization_firmware_enabled: bool
    restart_required: bool = False

    @property
    def ready(self) -> bool:
        return (
            self.is_windows
            and self.hyperv_available
            and self.hyperv_enabled
            and self.virtualization_firmware_enabled
            and not self.restart_required
        )


@dataclass(frozen=True)
class WindowsVMConfig:
    name: str = "HMS-GPT-VPS-01"
    generation: int = 2
    memory_mb: int = 8192
    cpu_count: int = 4
    disk_size_gb: int = 80
    vm_root: Path = Path(r"C:\ProgramData\HMS-GPT-VPS\VMs")
    workspace_path: str = r"C:\HMS-Workspace"
    switch_name: str = "HMS-GPT-VPS-Internal"

    def validate(self) -> None:
        if not self.name.strip():
            raise ValueError("VM name is required")
        if self.generation != 2:
            raise ValueError("Only Hyper-V Generation 2 is supported")
        if self.memory_mb < 4096:
            raise ValueError("VM memory must be at least 4096 MB")
        if self.cpu_count < 2:
            raise ValueError("VM CPU count must be at least 2")
        if self.disk_size_gb < 40:
            raise ValueError("VM disk must be at least 40 GB")
        if not self.workspace_path.strip():
            raise ValueError("Workspace path is required")
        if not self.switch_name.strip():
            raise ValueError("Hyper-V switch name is required")


@dataclass(frozen=True)
class ProvisionPlan:
    phase: ProvisionPhase
    config: WindowsVMConfig
    requires_elevation: bool
    requires_restart: bool
    actions: tuple[str, ...]


def build_provision_plan(host: HyperVHostState, config: WindowsVMConfig) -> ProvisionPlan:
    """Build a deterministic plan without mutating the Windows host."""
    config.validate()

    if not host.is_windows:
        return ProvisionPlan(
            phase=ProvisionPhase.PREFLIGHT,
            config=config,
            requires_elevation=False,
            requires_restart=False,
            actions=("BLOCK: Windows host required",),
        )

    actions: list[str] = []
    requires_elevation = False
    requires_restart = host.restart_required

    if not host.virtualization_firmware_enabled:
        actions.append("BLOCK: enable CPU virtualization in firmware/BIOS")

    if not host.hyperv_available:
        actions.append("BLOCK: Hyper-V is unavailable on this Windows edition or hardware")
    elif not host.hyperv_enabled:
        actions.append("ENABLE: Hyper-V Windows feature after operator approval")
        requires_elevation = True
        requires_restart = True

    if actions:
        return ProvisionPlan(
            phase=ProvisionPhase.PREFLIGHT,
            config=config,
            requires_elevation=requires_elevation,
            requires_restart=requires_restart,
            actions=tuple(actions),
        )

    vm_dir = config.vm_root / config.name
    vhd_path = vm_dir / f"{config.name}.vhdx"
    actions.extend(
        (
            "ENSURE_INTERNAL_NAT_NETWORK",
            f"ENSURE_DIR: {vm_dir}",
            f"CREATE_VHDX: {vhd_path} size={config.disk_size_gb}GB dynamic",
            f"CREATE_VM: {config.name} generation={config.generation}",
            f"SET_MEMORY: {config.memory_mb}MB",
            f"SET_CPU: {config.cpu_count}",
            f"CONNECT_SWITCH: {config.switch_name}",
            "DISABLE_IMPLICIT_HOST_SHARES",
            f"CREATE_GUEST_WORKSPACE: {config.workspace_path}",
            "BOOTSTRAP_HMS_AGENT",
            "START_OUTBOUND_CONTROL_SESSION",
        )
    )

    return ProvisionPlan(
        phase=ProvisionPhase.HOST_READY,
        config=config,
        requires_elevation=False,
        requires_restart=False,
        actions=tuple(actions),
    )
