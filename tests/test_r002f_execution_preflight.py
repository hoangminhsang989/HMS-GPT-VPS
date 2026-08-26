from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.r002f_execution_preflight import (
    R002FExecutionPreflightRequest,
    _blocked_manifest,
    build_one_shot_argv,
    derive_trust_root_certificate_path,
    render_powershell_command,
)


def _request(tmp_path: Path) -> R002FExecutionPreflightRequest:
    return R002FExecutionPreflightRequest(
        repo_root=tmp_path / "repo",
        proof_path=tmp_path / "preflight.json",
        package_root=tmp_path / "package",
        package_manifest=tmp_path / "package.json",
        runtime_config=tmp_path / "agent-runtime.json",
        instance_registry=tmp_path / "instances.json",
        instance_runtime_dir=tmp_path / "runtime",
        bridge_device_credential=tmp_path / "device.dpapi",
        challenge_source_commit="1" * 40,
        challenge_workspace_path="README.md",
        challenge_expected_sha256="2" * 64,
    )


def test_powershell_command_quotes_each_argument() -> None:
    command = render_powershell_command(["python.exe", "C:\\A B\\x.py", "a'b"])
    assert command == "& 'python.exe' 'C:\\A B\\x.py' 'a''b'"


def test_trust_root_derives_server_certificate_only_for_equal_authority(tmp_path: Path) -> None:
    path = derive_trust_root_certificate_path(
        configured_path=None,
        tls_certificate_path=str(tmp_path / "server.pem"),
        tls_certificate_der_sha256="a" * 64,
        trust_root_der_sha256="a" * 64,
    )
    assert path == (tmp_path / "server.pem").absolute()


def test_distinct_trust_root_digest_requires_explicit_authority(tmp_path: Path) -> None:
    assert derive_trust_root_certificate_path(
        configured_path=None,
        tls_certificate_path=str(tmp_path / "server.pem"),
        tls_certificate_der_sha256="a" * 64,
        trust_root_der_sha256="b" * 64,
    ) is None


def test_explicit_trust_root_authority_wins(tmp_path: Path) -> None:
    explicit = tmp_path / "root.pem"
    assert derive_trust_root_certificate_path(
        configured_path=explicit,
        tls_certificate_path=str(tmp_path / "server.pem"),
        tls_certificate_der_sha256="a" * 64,
        trust_root_der_sha256="b" * 64,
    ) == explicit.absolute()


def test_blocked_manifest_prefers_missing_authority() -> None:
    proof = _blocked_manifest(
        runner_source_commit="1" * 40,
        missing_authority=["runtime_config"],
        host_blockers=["HYPERV_HOST_NOT_READY"],
        authority_blockers=[],
        derived={},
        bootstrap_secret_environment_absent=True,
    )
    assert proof["status"] == "BLOCKED_MISSING_AUTHORITY"
    assert proof["execution_started"] is False


def test_blocked_manifest_uses_host_status_when_authority_is_complete() -> None:
    proof = _blocked_manifest(
        runner_source_commit="1" * 40,
        missing_authority=[],
        host_blockers=["WINDOWS_ADMINISTRATOR_REQUIRED"],
        authority_blockers=[],
        derived={},
        bootstrap_secret_environment_absent=True,
    )
    assert proof["status"] == "BLOCKED_HOST_PRECONDITION"
    assert proof["bootstrap_environment_required_at_execution"] is True


def test_request_rejects_step_timeout_not_above_external(tmp_path: Path) -> None:
    request = _request(tmp_path)
    request = R002FExecutionPreflightRequest(
        **{
            **request.__dict__,
            "external_timeout_seconds": 300.0,
            "step_timeout_seconds": 300.0,
        }
    )
    with pytest.raises(ValueError):
        request.validate_shape()


def test_one_shot_argv_contains_no_bootstrap_secret_environment(tmp_path: Path) -> None:
    request = _request(tmp_path)
    argv = build_one_shot_argv(
        request=request,
        runner_source_commit="3" * 40,
        instance_id="instance-1",
        vm_name="HMS-VM-1",
        run_dir=tmp_path / "run",
        provision_state=tmp_path / "provision-state.json",
        trust_root_certificate=tmp_path / "root.pem",
    )
    joined = "\n".join(argv)
    assert "HMS_MANAGED_GUEST_BOOTSTRAP_USERNAME" not in joined
    assert "HMS_MANAGED_GUEST_BOOTSTRAP_PASSWORD" not in joined
    assert "--runner-source-commit" in argv
    assert "3" * 40 in argv
