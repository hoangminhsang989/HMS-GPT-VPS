from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hms_gpt_vps.bridge_composite_activation_runner import (
    BOOTSTRAP_PASSWORD_ENV,
    BOOTSTRAP_USERNAME_ENV,
)
from hms_gpt_vps.r002f_one_shot_production_qualification import (
    FAILURE_MARKER_NAME,
    FINAL_MANIFEST_NAME,
    OPENAI_CHALLENGE_NAME,
    R002FOneShotProductionQualificationError,
    R002FOneShotProductionQualificationRequest,
    run_r002f_one_shot_production_qualification,
)


RUNNER_COMMIT = "a" * 40
CHALLENGE_COMMIT = "b" * 40
EXPECTED_SHA256 = "c" * 64
USERNAME = "bootstrap-user"
PASSWORD = "secret-bootstrap-password"


def _touch(path: Path, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _request(tmp_path: Path, *, run_inside_repo: bool = False) -> R002FOneShotProductionQualificationRequest:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    scripts = repo / "scripts"
    scripts.mkdir()
    for name in (
        "qualify_managed_hyperv_agent.py",
        "qualify_hms_bridge_composite_activation.py",
        "qualify_hms_bridge_composite_agent_transport.py",
        "qualify_hms_bridge_openai_control_plane_command_flow.py",
    ):
        _touch(scripts / name, b"print('stub')\n")

    inputs = tmp_path / "inputs"
    package_root = inputs / "package"
    package_root.mkdir(parents=True)
    instance_runtime = inputs / "runtime"
    instance_runtime.mkdir(parents=True)
    package_manifest = _touch(inputs / "package-manifest.json", b"{}\n")
    runtime_config = _touch(inputs / "runtime-config.json", b"{}\n")
    registry = _touch(inputs / "registry.json", b"{}\n")
    provision = _touch(inputs / "provision.json", b"{}\n")
    device = _touch(inputs / "device.json", b"{}\n")
    trust = _touch(inputs / "trust.pem", b"CERT\n")
    run_parent = repo if run_inside_repo else tmp_path / "proofs"
    if not run_inside_repo:
        run_parent.mkdir()

    return R002FOneShotProductionQualificationRequest(
        repo_root=repo,
        run_dir=run_parent / "run-001",
        runner_source_commit=RUNNER_COMMIT,
        instance_id="instance-001",
        vm_name="HMS-GPT-VPS-001",
        package_root=package_root,
        package_manifest=package_manifest,
        runtime_config=runtime_config,
        instance_registry=registry,
        provision_state=provision,
        instance_runtime_dir=instance_runtime,
        bridge_device_credential=device,
        trust_root_certificate=trust,
        challenge_source_commit=CHALLENGE_COMMIT,
        challenge_workspace_path="README.md",
        challenge_expected_sha256=EXPECTED_SHA256,
    )


def _environment() -> dict[str, str]:
    return {
        "PATH": "test-path",
        BOOTSTRAP_USERNAME_ENV: USERNAME,
        BOOTSTRAP_PASSWORD_ENV: PASSWORD,
        "PYTHONPATH": "hostile-pythonpath",
        "PYTHONHOME": "hostile-pythonhome",
    }


def _cross_result() -> dict[str, object]:
    return {
        "qualification": "R002F_PRODUCTION_CROSS_PROOF_GATE",
        "instance_id": "instance-001",
        "source_commit": CHALLENGE_COMMIT,
        "vm_id": "12345678-1234-1234-1234-123456789abc",
        "device_id": "device-001",
        "agent_boot_id": "boot-001",
        "tunnel_executable_sha256": "d" * 64,
        "cross_proof_identity_binding_proven": True,
        "full_bridge_command_flow_proven": False,
        "chatgpt_ui_origin_proven": False,
    }


def test_one_shot_runs_four_live_steps_without_secrets_in_argv(tmp_path: Path) -> None:
    request = _request(tmp_path)
    calls: list[tuple[list[str], dict[str, str]]] = []
    checkout_environments: list[dict[str, str]] = []

    def checkout_validator(repo_root, expected_commit, *, environment):  # type: ignore[no-untyped-def]
        assert repo_root == request.repo_root
        assert expected_commit == RUNNER_COMMIT
        env = dict(environment)
        assert BOOTSTRAP_USERNAME_ENV not in env
        assert BOOTSTRAP_PASSWORD_ENV not in env
        checkout_environments.append(env)

    def command_runner(argv, *, cwd, env, check, timeout):  # type: ignore[no-untyped-def]
        args = list(argv)
        child_env = dict(env)
        calls.append((args, child_env))
        assert cwd == str(request.repo_root)
        assert check is False
        assert timeout == request.step_timeout_seconds
        assert USERNAME not in args
        assert PASSWORD not in args
        assert child_env[BOOTSTRAP_USERNAME_ENV] == USERNAME
        assert child_env[BOOTSTRAP_PASSWORD_ENV] == PASSWORD
        assert "PYTHONPATH" not in child_env
        assert "PYTHONHOME" not in child_env
        assert child_env["PYTHONNOUSERSITE"] == "1"
        assert "-I" in args
        assert "-X" in args
        assert "utf8" in args
        assert str(request.repo_root / "src") in args

        proof_index = args.index("--proof") + 1
        _touch(Path(args[proof_index]), b'{"component":true}\n')
        if "--challenge" in args:
            challenge_index = args.index("--challenge") + 1
            _touch(Path(args[challenge_index]), b'{"challenge":true}\n')
        return SimpleNamespace(returncode=0)

    def cross_verifier(**kwargs):  # type: ignore[no-untyped-def]
        output = kwargs["output_proof_path"]
        _touch(output, b'{"cross":true}\n')
        result = _cross_result()
        result["source_commit"] = CHALLENGE_COMMIT
        result["managed_hyperv_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["managed_hyperv_proof_path"].read_bytes()
        ).hexdigest()
        result["composite_activation_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["composite_activation_proof_path"].read_bytes()
        ).hexdigest()
        result["authenticated_agent_transport_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["agent_transport_proof_path"].read_bytes()
        ).hexdigest()
        result["openai_control_plane_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["openai_control_plane_proof_path"].read_bytes()
        ).hexdigest()
        return result

    result = run_r002f_one_shot_production_qualification(
        request,
        environment=_environment(),
        python_executable="python-test",
        command_runner=command_runner,
        administrator_preflight=lambda: None,
        checkout_validator=checkout_validator,
        cross_proof_verifier=cross_verifier,
    )

    assert len(calls) == 4
    assert checkout_environments
    assert result["status"] == "COMPONENT_LIVE_PROOFS_CROSS_BOUND"
    assert result["runner_source_commit"] == RUNNER_COMMIT
    assert result["challenge_source_commit"] == CHALLENGE_COMMIT
    assert result["full_bridge_command_flow_proven"] is False
    assert result["chatgpt_ui_origin_proven"] is False
    assert (request.run_dir / FINAL_MANIFEST_NAME).is_file()
    assert (request.run_dir / OPENAI_CHALLENGE_NAME).is_file()
    assert not (request.run_dir / FAILURE_MARKER_NAME).exists()

    published = json.loads((request.run_dir / FINAL_MANIFEST_NAME).read_text("utf-8"))
    assert published == result


def test_one_shot_stops_after_first_failed_child_and_keeps_forensic_marker(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    calls: list[str] = []

    def command_runner(argv, **kwargs):  # type: ignore[no-untyped-def]
        args = list(argv)
        proof = Path(args[args.index("--proof") + 1])
        if any("qualify_managed_hyperv_agent.py" in item for item in args):
            calls.append("managed")
            _touch(proof, b'{"component":true}\n')
            return SimpleNamespace(returncode=0)
        calls.append("activation")
        return SimpleNamespace(returncode=17)

    with pytest.raises(R002FOneShotProductionQualificationError) as exc_info:
        run_r002f_one_shot_production_qualification(
            request,
            environment=_environment(),
            python_executable="python-test",
            command_runner=command_runner,
            administrator_preflight=lambda: None,
            checkout_validator=lambda *args, **kwargs: None,
            cross_proof_verifier=lambda **kwargs: pytest.fail("cross gate must not run"),
        )

    assert exc_info.value.step == "composite-activation"
    assert exc_info.value.exit_code == 17
    assert calls == ["managed", "activation"]
    assert not (request.run_dir / FINAL_MANIFEST_NAME).exists()
    marker = json.loads((request.run_dir / FAILURE_MARKER_NAME).read_text("utf-8"))
    assert marker["status"] == "FAILED_CLOSED"
    assert marker["failed_step"] == "composite-activation"
    assert marker["exit_code"] == 17
    assert marker["proof_authority"] is False
    assert PASSWORD not in json.dumps(marker)


def test_one_shot_rejects_run_directory_inside_source_checkout(tmp_path: Path) -> None:
    request = _request(tmp_path, run_inside_repo=True)
    with pytest.raises(ValueError, match="outside"):
        request.validate()


@pytest.mark.parametrize(
    ("external_timeout", "step_timeout"),
    [
        (29.0, 900.0),
        (300.0, 300.0),
        (300.0, 3601.0),
        (float("nan"), 900.0),
    ],
)
def test_one_shot_timeout_contract_is_bounded(
    tmp_path: Path,
    external_timeout: float,
    step_timeout: float,
) -> None:
    request = _request(tmp_path)
    request = R002FOneShotProductionQualificationRequest(
        **{
            **request.__dict__,
            "external_timeout_seconds": external_timeout,
            "step_timeout_seconds": step_timeout,
        }
    )
    with pytest.raises(ValueError):
        request.validate()


def test_invalid_cross_proof_boundary_fails_closed_without_final_manifest(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)

    def command_runner(argv, **kwargs):  # type: ignore[no-untyped-def]
        args = list(argv)
        _touch(Path(args[args.index("--proof") + 1]), b'{"component":true}\n')
        if "--challenge" in args:
            _touch(Path(args[args.index("--challenge") + 1]), b'{"challenge":true}\n')
        return SimpleNamespace(returncode=0)

    def cross_verifier(**kwargs):  # type: ignore[no-untyped-def]
        _touch(kwargs["output_proof_path"], b'{"cross":true}\n')
        invalid = _cross_result()
        invalid["source_commit"] = CHALLENGE_COMMIT
        invalid["managed_hyperv_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["managed_hyperv_proof_path"].read_bytes()
        ).hexdigest()
        invalid["composite_activation_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["composite_activation_proof_path"].read_bytes()
        ).hexdigest()
        invalid["authenticated_agent_transport_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["agent_transport_proof_path"].read_bytes()
        ).hexdigest()
        invalid["openai_control_plane_proof_sha256"] = __import__("hashlib").sha256(
            kwargs["openai_control_plane_proof_path"].read_bytes()
        ).hexdigest()
        invalid["full_bridge_command_flow_proven"] = True
        return invalid

    with pytest.raises(R002FOneShotProductionQualificationError) as exc_info:
        run_r002f_one_shot_production_qualification(
            request,
            environment=_environment(),
            python_executable="python-test",
            command_runner=command_runner,
            administrator_preflight=lambda: None,
            checkout_validator=lambda *args, **kwargs: None,
            cross_proof_verifier=cross_verifier,
        )

    assert exc_info.value.step == "cross-proof"
    assert not (request.run_dir / FINAL_MANIFEST_NAME).exists()
    assert (request.run_dir / FAILURE_MARKER_NAME).is_file()
