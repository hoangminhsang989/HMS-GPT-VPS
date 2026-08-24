from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from hms_gpt_vps.agent_device_credential_store import BridgeAgentDeviceCredentialStore
from hms_gpt_vps.agent_package_transfer_attempt_factory import (
    create_dpapi_agent_package_transfer_attempt_store,
)
from hms_gpt_vps.agent_service_install import AgentServiceConfig
from hms_gpt_vps.agent_service_runtime_config import load_agent_service_runtime_config
from hms_gpt_vps.managed_agent_provisioning_runtime import (
    ManagedAgentProvisioningConfig,
    ManagedAgentProvisioningRuntime,
)
from hms_gpt_vps.managed_agent_reconcile_runtime import ManagedAgentReconcileRuntime
from hms_gpt_vps.managed_hyperv_agent_qualification import (
    qualify_managed_hyperv_agent,
    write_managed_hyperv_agent_qualification_proof,
)
from hms_gpt_vps.powershell_direct import PowerShellDirectCredential
from hms_gpt_vps.provisioning import ProvisionContext, ProvisioningOrchestrator
from hms_gpt_vps.windows_provisioner import HyperVHostState, WindowsVMConfig


BOOTSTRAP_USERNAME_ENV = "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME"
BOOTSTRAP_PASSWORD_ENV = "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _path_chain_has_redirect(path: Path) -> bool:
    chain: list[Path] = []
    current = path.expanduser().absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if candidate.is_symlink():
            return True
        try:
            stat_result = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = int(getattr(stat_result, "st_file_attributes", 0))
        if attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return True
    return False


def _absolute_existing_file(raw: str, label: str) -> Path:
    path = Path(raw).expanduser().absolute()
    if _path_chain_has_redirect(path) or not path.is_file():
        raise ValueError(
            f"{label} must be an existing file whose path chain has no link/reparse redirect"
        )
    return path


def _absolute_existing_dir(raw: str, label: str) -> Path:
    path = Path(raw).expanduser().absolute()
    if _path_chain_has_redirect(path) or not path.is_dir():
        raise ValueError(
            f"{label} must be an existing directory whose path chain has no link/reparse redirect"
        )
    return path


def _new_proof_path(raw: str) -> Path:
    path = Path(raw).expanduser().absolute()
    if path.exists() or _path_chain_has_redirect(path):
        raise ValueError(
            "qualification proof path must be absent and must not traverse a link/reparse point"
        )
    parent = path.parent
    if not parent.is_dir():
        raise ValueError("qualification proof parent must be an existing directory")
    return path


def _load_bootstrap_credential() -> PowerShellDirectCredential:
    username = os.environ.pop(BOOTSTRAP_USERNAME_ENV, "")
    password = os.environ.pop(BOOTSTRAP_PASSWORD_ENV, "")
    if not username.strip():
        raise ValueError(f"{BOOTSTRAP_USERNAME_ENV} is required")
    if not password:
        raise ValueError(f"{BOOTSTRAP_PASSWORD_ENV} is required")
    credential = PowerShellDirectCredential(username=username, password=password)
    credential.validate()
    return credential


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify the HMS Agent inside one existing managed Hyper-V Windows guest. "
            "This command does not create/delete the VM or retire bootstrap credentials."
        )
    )
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--package-root", required=True)
    parser.add_argument("--package-manifest", required=True)
    parser.add_argument("--runtime-config", required=True)
    parser.add_argument("--instance-registry", required=True)
    parser.add_argument("--provision-state", required=True)
    parser.add_argument("--instance-runtime-dir", required=True)
    parser.add_argument("--bridge-device-credential", required=True)
    parser.add_argument("--proof", required=True)
    parser.add_argument("--max-reconcile-steps", type=int, default=8)
    return parser


def main(argv: list[str] | None = None) -> int:
    if os.name != "nt":
        raise RuntimeError("managed Hyper-V Agent qualification requires Windows")

    args = build_parser().parse_args(argv)
    if not args.instance_id.strip() or not args.vm_name.strip():
        raise ValueError("instance-id and vm-name are required")

    package_root = _absolute_existing_dir(args.package_root, "package-root")
    package_manifest = _absolute_existing_file(args.package_manifest, "package-manifest")
    runtime_config_path = _absolute_existing_file(args.runtime_config, "runtime-config")
    registry_path = _absolute_existing_file(args.instance_registry, "instance-registry")
    provision_state_path = _absolute_existing_file(args.provision_state, "provision-state")
    instance_runtime_dir = _absolute_existing_dir(
        args.instance_runtime_dir,
        "instance-runtime-dir",
    )
    bridge_credential_path = _absolute_existing_file(
        args.bridge_device_credential,
        "bridge-device-credential",
    )
    proof_path = _new_proof_path(args.proof)

    runtime_config = load_agent_service_runtime_config(runtime_config_path)
    if runtime_config.instance_id != args.instance_id:
        raise ValueError("runtime config belongs to another instance")

    bootstrap_credential = _load_bootstrap_credential()
    bridge_credential = BridgeAgentDeviceCredentialStore(
        bridge_credential_path
    ).load(expected_instance_id=args.instance_id)

    service = AgentServiceConfig()
    managed_config = ManagedAgentProvisioningConfig(
        instance_id=args.instance_id,
        vm_name=args.vm_name,
        package_source_root=package_root,
        package_manifest_path=package_manifest,
        registry_path=registry_path,
        service=service,
        runtime=runtime_config,
    )
    attempt_store = create_dpapi_agent_package_transfer_attempt_store(instance_runtime_dir)
    agent_runtime = ManagedAgentProvisioningRuntime(managed_config, attempt_store)
    orchestrator = ProvisioningOrchestrator(provision_state_path)
    reconcile_runtime = ManagedAgentReconcileRuntime(orchestrator, agent_runtime)

    # Host/image fields are not consumed by AGENT_INSTALLING/AGENT_SERVICE_READY
    # transitions. Hyper-V authority for this tranche comes from the production
    # runtime's persisted VMId + Get-VM -Id readback before every guest action.
    context = ProvisionContext(
        instance_id=args.instance_id,
        config=WindowsVMConfig(
            name=args.vm_name,
            workspace_path=service.workspace_path,
        ),
        host=HyperVHostState(
            is_windows=True,
            hyperv_available=True,
            hyperv_enabled=True,
            virtualization_firmware_enabled=True,
            restart_required=False,
        ),
        image=None,
    )

    proof = qualify_managed_hyperv_agent(
        reconcile_runtime,
        context,
        bootstrap_credential,
        bridge_credential,
        max_reconcile_steps=args.max_reconcile_steps,
    )
    write_managed_hyperv_agent_qualification_proof(proof_path, proof)
    print(json.dumps(proof.to_dict(), ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Keep stdout clean for a successful proof JSON. Failure diagnostics must
        # not echo bootstrap/device secret values or child environments.
        print(
            f"managed Hyper-V Agent qualification failed: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
