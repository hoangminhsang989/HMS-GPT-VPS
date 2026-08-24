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
    runtime_marker = Path(service.binary_path).parent / RUNTIME_MARKER
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
    package_dir = Path(sys.argv[1]).resolve(strict=True)
    service = AgentServiceConfig()
    service.validate()

    if _service_exists(service.service_name):
        raise RuntimeError("HMSAgent already exists before service-start probe")
    if Path(service.runtime_path).exists() or Path(service.workspace_path).exists():
        raise RuntimeError("managed HMS paths already exist before service-start probe")

    executable = (package_dir / "hms-agent.exe").resolve(strict=True)
    manifest = load_agent_package_manifest((package_dir / "hms-agent.manifest.json").resolve(strict=True))
    verify_agent_package(executable, manifest)
    require_windows_amd64_pe(executable)

    runtime_token = secrets.token_hex(24)
    workspace_token = secrets.token_hex(24)
    agent_root = Path(service.binary_path).parent
    state_root = Path(service.state_path)
    workspace_root = Path(service.workspace_path)
    agent_root.mkdir(parents=True)
    state_root.mkdir(parents=True)
    workspace_root.mkdir(parents=True)
    (agent_root / RUNTIME_MARKER).write_text(runtime_token, encoding="utf-8")
    (workspace_root / WORKSPACE_MARKER).write_text(workspace_token, encoding="utf-8")
    shutil.copy2(executable, Path(service.binary_path))

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
        install = run_powershell_json(
            build_agent_service_install_script(
                service,
                expected_sha256=manifest.sha256,
                runtime_config=runtime,
            ),
            timeout_seconds=180,
        )
        ready = bool(install.get("ready", False))
        print(
            json.dumps(
                {
                    "installer_ready": ready,
                    "installer_status": str(install.get("status", "")),
                    "installer_start_name": str(install.get("start_name", "")),
                    "installer_sid_type": str(install.get("service_sid_type", "")),
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
