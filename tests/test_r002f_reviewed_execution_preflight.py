from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hms_gpt_vps.bridge_composite_activation_runner import (
    BOOTSTRAP_PASSWORD_ENV,
    BOOTSTRAP_USERNAME_ENV,
)
from hms_gpt_vps.r002f_execution_preflight import R002FExecutionPreflightRequest
from hms_gpt_vps.r002f_reviewed_execution_preflight import (
    R002FReviewedCheckoutAuthorityError,
    R002FReviewedExecutionPreflightError,
    checkout_validation_environment,
    require_reviewed_clean_checkout,
    run_r002f_reviewed_execution_preflight,
    sanitize_git_control_environment,
)


EXPECTED_COMMIT = "a" * 40


def _request(tmp_path: Path) -> R002FExecutionPreflightRequest:
    return R002FExecutionPreflightRequest(
        repo_root=tmp_path / "repo",
        proof_path=tmp_path / "unused.json",
        package_root=tmp_path / "package",
        package_manifest=tmp_path / "package.json",
        runtime_config=tmp_path / "agent-runtime.json",
        instance_registry=tmp_path / "instances.json",
        instance_runtime_dir=tmp_path / "runtime",
        bridge_device_credential=tmp_path / "device.dpapi",
        challenge_source_commit="b" * 40,
        challenge_workspace_path="README.md",
        challenge_expected_sha256="c" * 64,
    )


def test_git_control_environment_is_removed_case_insensitively() -> None:
    env = sanitize_git_control_environment(
        {
            "PATH": "safe-path",
            "GIT_DIR": "evil-dir",
            "git_work_tree": "evil-tree",
            "Git_Index_File": "evil-index",
            BOOTSTRAP_USERNAME_ENV: "user",
            BOOTSTRAP_PASSWORD_ENV: "secret",
        }
    )
    assert env["PATH"] == "safe-path"
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert not any(
        key.casefold().startswith("git_") and key != "GIT_NO_REPLACE_OBJECTS"
        for key in env
    )
    assert env[BOOTSTRAP_USERNAME_ENV] == "user"
    assert env[BOOTSTRAP_PASSWORD_ENV] == "secret"


def test_checkout_environment_also_removes_bootstrap_secrets() -> None:
    env = checkout_validation_environment(
        {
            "PATH": "safe-path",
            BOOTSTRAP_USERNAME_ENV.lower(): "user",
            BOOTSTRAP_PASSWORD_ENV: "secret",
        }
    )
    assert BOOTSTRAP_PASSWORD_ENV not in env
    assert not any(
        key.casefold() == BOOTSTRAP_USERNAME_ENV.casefold() for key in env
    )


def test_reviewed_checkout_requires_external_expected_head_and_clean_index(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    observed_envs: list[dict[str, str]] = []

    def runner(argv, **kwargs):  # type: ignore[no-untyped-def]
        observed_envs.append(dict(kwargs["env"]))
        args = list(argv)
        if args[-2:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(repo) + "\n")
        if args[-3:] == ["rev-parse", "--verify", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=EXPECTED_COMMIT + "\n")
        if "status" in args:
            return SimpleNamespace(returncode=0, stdout="")
        if "ls-files" in args:
            return SimpleNamespace(returncode=0, stdout="H a.py\x00H b.py\x00")
        raise AssertionError(args)

    require_reviewed_clean_checkout(
        repo,
        EXPECTED_COMMIT,
        environment={
            "PATH": "safe-path",
            "GIT_DIR": "evil-dir",
            BOOTSTRAP_PASSWORD_ENV: "secret",
        },
        command_runner=runner,
    )
    assert observed_envs
    for env in observed_envs:
        assert "GIT_DIR" not in env
        assert BOOTSTRAP_PASSWORD_ENV not in env
        assert env["GIT_NO_REPLACE_OBJECTS"] == "1"


def test_reviewed_checkout_rejects_head_mismatch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def runner(argv, **kwargs):  # type: ignore[no-untyped-def]
        args = list(argv)
        if args[-2:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(repo) + "\n")
        if args[-3:] == ["rev-parse", "--verify", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout="d" * 40 + "\n")
        raise AssertionError(args)

    with pytest.raises(
        R002FReviewedCheckoutAuthorityError,
        match="reviewed runner commit",
    ):
        require_reviewed_clean_checkout(
            repo,
            EXPECTED_COMMIT,
            environment={"PATH": "safe-path"},
            command_runner=runner,
        )


def test_reviewed_checkout_rejects_skip_worktree_or_non_normal_index_flags(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    def runner(argv, **kwargs):  # type: ignore[no-untyped-def]
        args = list(argv)
        if args[-2:] == ["rev-parse", "--show-toplevel"]:
            return SimpleNamespace(returncode=0, stdout=str(repo) + "\n")
        if args[-3:] == ["rev-parse", "--verify", "HEAD"]:
            return SimpleNamespace(returncode=0, stdout=EXPECTED_COMMIT + "\n")
        if "status" in args:
            return SimpleNamespace(returncode=0, stdout="")
        if "ls-files" in args:
            return SimpleNamespace(returncode=0, stdout="S src/hidden.py\x00")
        raise AssertionError(args)

    with pytest.raises(
        R002FReviewedCheckoutAuthorityError,
        match="index authority flags",
    ):
        require_reviewed_clean_checkout(
            repo,
            EXPECTED_COMMIT,
            environment={"PATH": "safe-path"},
            command_runner=runner,
        )


def test_reviewed_wrapper_injects_external_commit_authority_into_one_shot(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    request.repo_root.mkdir()
    proof_parent = tmp_path / "proofs"
    proof_parent.mkdir()
    final_proof = proof_parent / "reviewed.json"
    checkout_calls: list[str] = []

    def checkout_validator(repo_root, expected_commit, *, environment):  # type: ignore[no-untyped-def]
        assert repo_root == request.repo_root.absolute()
        assert expected_commit == EXPECTED_COMMIT
        assert "GIT_DIR" not in environment
        checkout_calls.append(expected_commit)

    def component_runner(component_request, *, environment):  # type: ignore[no-untyped-def]
        component = {
            "schema_version": 1,
            "qualification": "R002F_ZERO_MANUAL_EXECUTION_PREFLIGHT",
            "status": "READY_FOR_ONE_SHOT_EXECUTION",
            "ready": True,
            "runner_source_commit": EXPECTED_COMMIT,
            "missing_authority": [],
            "host_blockers": [],
            "authority_blockers": [],
            "derived": {"instance_id": "instance-1"},
            "bootstrap_secret_environment_absent": True,
            "bootstrap_environment_names": [
                BOOTSTRAP_USERNAME_ENV,
                BOOTSTRAP_PASSWORD_ENV,
            ],
            "one_shot_argv": [
                "python.exe",
                "run.py",
                "--runner-source-commit",
                EXPECTED_COMMIT,
                "--instance-id",
                "instance-1",
            ],
        }
        component_request.proof_path.write_text(
            json.dumps(component, sort_keys=True),
            encoding="utf-8",
        )
        return component

    result = run_r002f_reviewed_execution_preflight(
        request,
        expected_runner_source_commit=EXPECTED_COMMIT,
        final_proof_path=final_proof,
        environment={"PATH": "safe", "GIT_DIR": "evil"},
        checkout_validator=checkout_validator,
        component_runner=component_runner,
    )
    assert checkout_calls == [EXPECTED_COMMIT, EXPECTED_COMMIT]
    assert result["status"] == "READY_FOR_REVIEWED_ONE_SHOT_EXECUTION"
    assert result["reviewed_runner_source_commit"] == EXPECTED_COMMIT
    argv = result["one_shot_argv"]
    assert isinstance(argv, list)
    index = argv.index("--reviewed-runner-source-commit")
    assert argv[index + 1] == EXPECTED_COMMIT
    assert result["component_preflight_authority"] is False
    assert final_proof.is_file()


def test_reviewed_wrapper_rejects_component_commit_drift(tmp_path: Path) -> None:
    request = _request(tmp_path)
    request.repo_root.mkdir()
    proof_parent = tmp_path / "proofs"
    proof_parent.mkdir()

    def component_runner(component_request, *, environment):  # type: ignore[no-untyped-def]
        component = {
            "qualification": "R002F_ZERO_MANUAL_EXECUTION_PREFLIGHT",
            "status": "READY_FOR_ONE_SHOT_EXECUTION",
            "ready": True,
            "runner_source_commit": "d" * 40,
            "one_shot_argv": ["python", "run.py"],
        }
        component_request.proof_path.write_text("{}", encoding="utf-8")
        return component

    with pytest.raises(
        R002FReviewedExecutionPreflightError,
        match="different runner commit",
    ):
        run_r002f_reviewed_execution_preflight(
            request,
            expected_runner_source_commit=EXPECTED_COMMIT,
            final_proof_path=proof_parent / "reviewed.json",
            environment={"PATH": "safe"},
            checkout_validator=lambda *args, **kwargs: None,
            component_runner=component_runner,
        )
