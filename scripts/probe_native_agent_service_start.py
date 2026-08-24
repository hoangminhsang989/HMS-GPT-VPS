from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

from hms_gpt_vps.agent_device_credential_store import (
    GuestAgentDeviceCredentialStore,
    guest_device_credential_path,
)
from hms_gpt_vps.agent_package import (
    load_agent_package_manifest,
    require_windows_amd64_pe,
    verify_agent_package,
)
from hms_gpt_vps.agent_service_install import (
    AgentServiceConfig,
    build_agent_service_install_script,
)
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_DEVICE_SECRET_BYTES,
    AgentDeviceCredential,
)
from hms_gpt_vps.powershell import run_powershell_json


INSTANCE_ID = "ci-native-start-probe"
DEVICE_ID = "ci-native-start-probe-device"
PROJECT_ID = "ci-native-start-probe-project"
HEALTH_PORT = 18766
BRIDGE_ORIGIN = "https://127.0.0.1:9"
RUNTIME_MARKER = ".hms-ci-start-probe-owned"
WORKSPACE_MARKER = ".hms-ci-start-probe-workspace-owned"


def _require_ci_admin() -> None:
    if os.name != "nt":
        raise OSError("native service-start probe requires Windows")
    if os.environ.get("GITHUB_ACTIONS", "").casefold() != "true":
        raise PermissionError("native service-start probe is CI-only")
    if not bool(ctypes.windll.shell32.IsUserAnAdmin()):  # type: ignore[attr-defined]
        raise PermissionError("native service-start probe requires Administrator")


def _run_sc(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sc.exe", *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _print_sc(label: str, *args: str) -> subprocess.CompletedProcess[str]:
    completed = _run_sc(*args)
    payload = {
        "label": label,
        "argv": ["sc.exe", *args],
        "returncode": completed.returncode,
        "stdout": completed.stdout.strip(),
        "stderr": completed.stderr.strip(),
    }
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return completed


def _print_scm_event_tail() -> None:
    query = (
        "*[System[Provider[@Name='Service Control Manager'] and "
        "(EventID=7000 or EventID=7009 or EventID=7011 or EventID=7023 or "
        "EventID=7024 or EventID=7031 or EventID=7034)]]"
    )
    completed = subprocess.run(
        ["wevtutil.exe", "qe", "System", f"/q:{query}", "/c:8", "/rd:true", "/f:text"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    print(
        json.dumps(
            {
                "label": "scm_event_tail_before_cleanup",
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _print_failure_context(service_name: str) -> None:
    _print_sc("queryex_before_cleanup", "queryex", service_name)
    _print_sc("qc_before_cleanup", "qc", service_name)
    _print_sc("qsidtype_before_cleanup", "qsidtype", service_name)
    _print_scm_event_tail()


def _service_exists(name: str) -> bool:
    return _run_sc("query", name).returncode == 0


def _wait_service_absent(name: str, timeout_seconds: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _service_exists(name):
            return
        time.sleep(0.2)
    raise RuntimeError("service-start probe cleanup did not remove service")


def _cleanup(service: AgentServiceConfig, runtime_token: str, workspace_token: str) -> None:
    if _service_exists(service.service_name):
        _run_sc("stop", service.service_name)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            query = _run_sc("query", service.service_name)
            if query.returncode != 0 or "STOPPED" in query.stdout:
                break
            time.sleep(0.2)
        deleted = _run_sc("delete", service.service_name)
        if deleted.returncode not in {0, 1060}:
            raise RuntimeError("service-start probe sc delete failed")
        _wait_service_absent(service.service_name)

    runtime_root = Path(service.runtime_path)
    runtime_marker = runtime_root / RUNTIME_MARKER
    if runtime_root.exists():
        if not runtime_marker.is_file() or runtime_marker.read_text(encoding="utf-8") != runtime_token:
            raise PermissionError("refusing to remove unowned start-probe runtime")
        shutil.rmtree(runtime_root)

    workspace_root = Path(service.workspace_path)
    workspace_marker = workspace_root / WORKSPACE_MARKER
    if workspace_root.exists():
        if not workspace_marker.is_file() or workspace_marker.read_text(encoding="utf-8") != workspace_token:
            raise PermissionError("refusing to remove unowned start-probe workspace")
        shutil.rmtree(workspace_root)


def main() -> int:
    _require_ci_admin()
    artifact_root = Path(sys.argv[1]).resolve(strict=True)
    service = AgentServiceConfig()
    service.validate()

    if _service_exists(service.service_name):
        raise RuntimeError("HMSAgent already exists before service-start probe")
    if Path(service.runtime_path).exists() or Path(service.workspace_path).exists():
        raise RuntimeError("managed HMS paths already exist before service-start probe")

    source_package = artifact_root / "hms-agent"
    manifest = load_agent_package_manifest(
        (artifact_root / "hms-agent.manifest.json").resolve(strict=True)
    )
    verify_agent_package(source_package, manifest)
    source_entrypoint = source_package / manifest.entrypoint
    require_windows_amd64_pe(source_entrypoint)

    runtime_token = secrets.token_hex(24)
    workspace_token = secrets.token_hex(24)
    runtime_root = Path(service.runtime_path)
    agent_root = Path(service.agent_root_path)
    target_package = Path(service.package_path)
    state_root = Path(service.state_path)
    workspace_root = Path(service.workspace_path)
    runtime_root.mkdir(parents=True)
    (runtime_root / RUNTIME_MARKER).write_text(runtime_token, encoding="utf-8")
    agent_root.mkdir(parents=True)
    state_root.mkdir(parents=True)
    workspace_root.mkdir(parents=True)
    (workspace_root / WORKSPACE_MARKER).write_text(workspace_token, encoding="utf-8")
    shutil.copytree(source_package, target_package)
    verify_agent_package(target_package, manifest)
    require_windows_amd64_pe(Path(service.binary_path))

    GuestAgentDeviceCredentialStore(guest_device_credential_path(state_root)).save_create_only(
        AgentDeviceCredential(
            instance_id=INSTANCE_ID,
            device_id=DEVICE_ID,
            secret=secrets.token_bytes(AGENT_DEVICE_SECRET_BYTES),
        )
    )

    git = shutil.which("git.exe") or shutil.which("git")
    if not git:
        raise FileNotFoundError("git executable unavailable")
    runtime = AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id=INSTANCE_ID,
        project_id=PROJECT_ID,
        bridge_origin=BRIDGE_ORIGIN,
        workspace_root=service.workspace_path,
        state_root=service.state_path,
        python_executable=str(Path(sys.executable).resolve(strict=True)),
        git_executable=str(Path(git).resolve(strict=True)),
        health_port=HEALTH_PORT,
    )
    runtime.validate()

    ready = False
    try:
        try:
            install = run_powershell_json(
                build_agent_service_install_script(
                    service,
                    package_manifest=manifest,
                    runtime_config=runtime,
                ),
                timeout_seconds=180,
            )
        except BaseException:
            _print_failure_context(service.service_name)
            raise

        ready = bool(install.get("ready", False))
        if int(install.get("package_file_count", 0)) != manifest.file_count:
            raise RuntimeError("installer package file-count proof mismatch")
        if int(install.get("package_total_size", 0)) != manifest.total_size:
            raise RuntimeError("installer package size proof mismatch")
        print(
            json.dumps(
                {
                    "installer_ready": ready,
                    "installer_status": str(install.get("status", "")),
                    "installer_start_name": str(install.get("start_name", "")),
                    "installer_sid_type": str(install.get("service_sid_type", "")),
                    "package_schema": 2,
                    "package_file_count": manifest.file_count,
                    "package_total_size": manifest.total_size,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        _print_sc("queryex_before_cleanup", "queryex", service.service_name)
        _print_sc("qc_before_cleanup", "qc", service.service_name)
        _print_sc("qsidtype_before_cleanup", "qsidtype", service.service_name)
    finally:
        _cleanup(service, runtime_token, workspace_token)

    if not ready:
        raise RuntimeError("packaged Agent did not remain Running in SCM start probe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
