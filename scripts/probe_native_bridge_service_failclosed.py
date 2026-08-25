from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time

from hms_gpt_vps.bridge_native_scm_failclosed import (
    validate_bridge_native_scm_failclosed_observation,
)
from hms_gpt_vps.bridge_package import (
    load_bridge_package_manifest,
    require_bridge_windows_amd64_pe,
    verify_bridge_package,
)
from hms_gpt_vps.bridge_service_config_storage import (
    DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
)
from hms_gpt_vps.bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
)
from hms_gpt_vps.powershell import ps_literal, run_powershell_json


BRIDGE_PORT = 9443
DISPLAY_NAME = "HMS GPT VPS Bridge"
OWNED_MARKER = ".hms-ci-native-bridge-scm-owned"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Qualify packaged HMSBridge SCM fail-closed startup on Windows CI"
    )
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("proof", type=Path)
    return parser


def _require_ci_admin() -> None:
    if os.name != "nt":
        raise OSError("native HMSBridge SCM probe requires Windows")
    if os.environ.get("GITHUB_ACTIONS", "").casefold() != "true":
        raise PermissionError("native HMSBridge SCM probe is CI-only")
    if not bool(ctypes.windll.shell32.IsUserAnAdmin()):  # type: ignore[attr-defined]
        raise PermissionError("native HMSBridge SCM probe requires Administrator")


def _run_sc(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sc.exe", *args],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )


def _require_sc_ok(label: str, *args: str) -> subprocess.CompletedProcess[str]:
    completed = _run_sc(*args)
    if completed.returncode != 0:
        raise RuntimeError(
            f"{label} failed: rc={completed.returncode}; "
            f"stdout={completed.stdout.strip()!r}; stderr={completed.stderr.strip()!r}"
        )
    return completed


def _service_exists() -> bool:
    return _run_sc("query", HMS_BRIDGE_SERVICE_NAME).returncode == 0


def _wait_service_absent(timeout_seconds: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _service_exists():
            return
        time.sleep(0.2)
    raise RuntimeError("native HMSBridge SCM cleanup did not remove service")


def _query_service() -> dict[str, object]:
    name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    return run_powershell_json(
        f"""
$ErrorActionPreference = 'Stop'
$rows = @(Get-CimInstance Win32_Service -Filter "Name={name}" -ErrorAction Stop)
if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge service' }}
$s = $rows[0]
[pscustomobject]@{{
  service_name = [string]$s.Name
  state = [string]$s.State
  start_mode = [string]$s.StartMode
  start_name = [string]$s.StartName
  path_name = [string]$s.PathName
  exit_code = [int64]$s.ExitCode
  service_specific_exit_code = [int64]$s.ServiceSpecificExitCode
}}
""".strip(),
        timeout_seconds=30,
    )


def _resolve_service_sid() -> str:
    account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    result = run_powershell_json(
        f"""
$ErrorActionPreference = 'Stop'
$account = [System.Security.Principal.NTAccount]::new({account})
$sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
[pscustomobject]@{{ service_sid = [string]$sid }}
""".strip(),
        timeout_seconds=30,
    )
    if frozenset(result) != {"service_sid"}:
        raise RuntimeError("HMSBridge service SID evidence schema is invalid")
    sid = result["service_sid"]
    if not isinstance(sid, str):
        raise RuntimeError("HMSBridge service SID evidence is invalid")
    return sid


def _service_sid_type() -> str:
    completed = _require_sc_ok(
        "query HMSBridge SID type", "qsidtype", HMS_BRIDGE_SERVICE_NAME
    )
    if "UNRESTRICTED" not in completed.stdout.upper():
        raise RuntimeError("HMSBridge service SID type is not UNRESTRICTED")
    return "UNRESTRICTED"


def _listener_absent() -> bool:
    result = run_powershell_json(
        f"""
$ErrorActionPreference = 'Stop'
$rows = @(Get-NetTCPConnection -State Listen -LocalPort {BRIDGE_PORT} -ErrorAction SilentlyContinue)
[pscustomobject]@{{ absent = [bool]($rows.Count -eq 0) }}
""".strip(),
        timeout_seconds=30,
    )
    if frozenset(result) != {"absent"} or not isinstance(result.get("absent"), bool):
        raise RuntimeError("Bridge listener evidence schema is invalid")
    return bool(result["absent"])


def _wait_for_deliberate_failure(timeout_seconds: float = 30.0) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    running_observed = False
    last: dict[str, object] | None = None
    while time.monotonic() < deadline:
        last = _query_service()
        if last.get("state") == "Running":
            running_observed = True
        if (
            last.get("state") == "Stopped"
            and int(last.get("exit_code", 0)) == 1066
            and int(last.get("service_specific_exit_code", 0)) != 0
        ):
            if running_observed:
                raise RuntimeError(
                    "HMSBridge reached Running during deliberate missing-config probe"
                )
            return last
        time.sleep(0.2)
    raise RuntimeError(f"HMSBridge did not reach deliberate fail-closed state: {last!r}")


def _cleanup(temp_root: Path, marker_token: str) -> None:
    if _service_exists():
        _run_sc("stop", HMS_BRIDGE_SERVICE_NAME)
        _run_sc("delete", HMS_BRIDGE_SERVICE_NAME)
        _wait_service_absent()
    if temp_root.exists():
        marker = temp_root / OWNED_MARKER
        if not marker.is_file() or marker.read_text(encoding="utf-8") != marker_token:
            raise PermissionError("refusing to remove unowned HMSBridge SCM probe root")
        shutil.rmtree(temp_root)


def main() -> int:
    _require_ci_admin()
    args = build_parser().parse_args()
    artifact_root = args.artifact_root.resolve(strict=True)
    proof_path = args.proof.resolve()
    production_root = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH.parent

    if _service_exists():
        raise RuntimeError("HMSBridge already exists before native SCM probe")
    if production_root.exists():
        raise RuntimeError(
            "fixed HMSBridge production runtime root already exists before fail-closed probe"
        )
    listener_absent_before = _listener_absent()
    if not listener_absent_before:
        raise RuntimeError("TCP port 9443 already has a listener before HMSBridge probe")

    package_root = artifact_root / "hms-bridge"
    manifest_path = (artifact_root / "hms-bridge.manifest.json").resolve(strict=True)
    manifest = load_bridge_package_manifest(manifest_path)
    verify_bridge_package(package_root, manifest)
    require_bridge_windows_amd64_pe(package_root / manifest.entrypoint)

    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    temp_root = runner_temp / ("hms-bridge-scm-" + secrets.token_hex(12))
    marker_token = secrets.token_hex(24)
    temp_root.mkdir()
    (temp_root / OWNED_MARKER).write_text(marker_token, encoding="utf-8")
    deployed = temp_root / "hms-bridge"
    shutil.copytree(package_root, deployed)
    verify_bridge_package(deployed, manifest)
    binary = (deployed / manifest.entrypoint).resolve(strict=True)
    require_bridge_windows_amd64_pe(binary)
    expected_command = f'"{binary}" service'

    proof: dict[str, object] | None = None
    cleanup_ok = False
    try:
        _require_sc_ok(
            "create HMSBridge",
            "create",
            HMS_BRIDGE_SERVICE_NAME,
            "type=",
            "own",
            "start=",
            "demand",
            "error=",
            "normal",
            "obj=",
            HMS_BRIDGE_SERVICE_ACCOUNT,
            "binPath=",
            expected_command,
            "DisplayName=",
            DISPLAY_NAME,
        )
        _require_sc_ok(
            "set HMSBridge SID type",
            "sidtype",
            HMS_BRIDGE_SERVICE_NAME,
            "unrestricted",
        )
        service_sid = _resolve_service_sid()
        sid_type = _service_sid_type()

        staged = _query_service()
        if (
            staged.get("state") != "Stopped"
            or staged.get("start_mode") != "Manual"
            or str(staged.get("start_name", "")).casefold()
            != HMS_BRIDGE_SERVICE_ACCOUNT.casefold()
            or staged.get("path_name") != expected_command
        ):
            raise RuntimeError("HMSBridge staged SCM authority differs before start")

        started = _run_sc("start", HMS_BRIDGE_SERVICE_NAME)
        print(
            json.dumps(
                {
                    "sc_start_returncode": started.returncode,
                    "sc_start_stdout": started.stdout.strip(),
                    "sc_start_stderr": started.stderr.strip(),
                },
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        stopped = _wait_for_deliberate_failure()
        listener_absent_after = _listener_absent()
        runtime_root_absent_after = not production_root.exists()

        observation = {
            **stopped,
            "service_sid": service_sid,
            "service_sid_type": sid_type,
            "binary_sha256": manifest.entrypoint_file.sha256,
            "listener_absent_before": listener_absent_before,
            "listener_absent_after": listener_absent_after,
            "runtime_root_absent_before": True,
            "runtime_root_absent_after": runtime_root_absent_after,
        }
        proof = validate_bridge_native_scm_failclosed_observation(
            observation,
            expected_binary_path=str(binary),
            expected_binary_sha256=manifest.entrypoint_file.sha256,
        )
        proof["source_commit"] = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=True,
            timeout=30,
        ).stdout.strip().lower()
    finally:
        _cleanup(temp_root, marker_token)
        cleanup_ok = not _service_exists() and not temp_root.exists()

    if proof is None:
        raise RuntimeError("native HMSBridge SCM proof was not produced")
    if not cleanup_ok:
        raise RuntimeError("native HMSBridge SCM cleanup did not converge")
    if production_root.exists():
        raise RuntimeError("HMSBridge fail-closed probe mutated production runtime root")
    proof["service_deleted_after_probe"] = True
    proof["temporary_package_deleted_after_probe"] = True
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    proof_path.write_text(
        json.dumps(
            proof,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(proof_path.read_text(encoding="utf-8").strip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
