from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
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
from hms_gpt_vps.r002f_reviewed_preflight_proof import reviewed_one_shot_argv
from hms_gpt_vps.r002f_reviewed_toolchain_authority import (
    R002FReviewedToolchainAuthorityError,
    pin_reviewed_git_executable,
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


def _git_authority(tmp_path: Path) -> tuple[Path, str]:
    path = tmp_path / ("git.exe" if os.name == "nt" else "git")
    path.write_bytes(b"reviewed-git-binary-authority")
    return path.absolute(), hashlib.sha256(path.read_bytes()).hexdigest()


def test_git_control_environment_is_removed_case_insensitively() -> None:
    env = sanitize_git_control_environment(
        {
            "PATH": "hostile-path",
            "GIT_DIR": "evil-dir",
            "git_work_tree": "evil-tree",
            "Git_Index_File": "evil-index",
            BOOTSTRAP_USERNAME_ENV: "user",
            BOOTSTRAP_PASSWORD_ENV: "secret",
        }
    )
    assert env["PATH"] == "hostile-path"
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1"
    assert not any(
        key.casefold().startswith("git_") and key != "GIT_NO_REPLACE_OBJECTS"
        for key in env
    )


def test_pinned_git_rejects_digest_mismatch(tmp_path: Path) -> None:
    git_path, _ = _git_authority(tmp_path)
    with pytest.raises(R002FReviewedToolchainAuthorityError, match="SHA-256"):
        with pin_reviewed_git_executable(git_path, "0" * 64):
            pytest.fail("mismatched Git authority must not enter")


def test_reviewed_checkout_uses_absolute_pinned_git_not_path_lookup(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git_path, git_sha = _git_authority(tmp_path)
    observed_commands: list[list[str]] = []
    observed_envs: list[dict[str, str]] = []

    def runner(argv, **kwargs):  # type: ignore[no-untyped-def]
        args = list(argv)
        observed_commands.append(args)
        observed_envs.append(dict(kwargs["env"]))
        assert args[0] == str(git_path)
        assert args[0] != "git"
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
        git_executable=git_path,
        git_executable_sha256=git_sha,
        environment={
            "PATH": str(tmp_path / "fake-bin"),
            "GIT_DIR": "evil-dir",
            BOOTSTRAP_PASSWORD_ENV: "secret",
        },
        command_runner=runner,
    )
    assert len(observed_commands) == 4
    for env in observed_envs:
        assert env["PATH"] == str(tmp_path / "fake-bin")
        assert "GIT_DIR" not in env
        assert BOOTSTRAP_PASSWORD_ENV not in env


def test_reviewed_checkout_rejects_head_mismatch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git_path, git_sha = _git_authority(tmp_path)

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
            git_executable=git_path,
            git_executable_sha256=git_sha,
            environment={"PATH": "hostile"},
            command_runner=runner,
        )


def test_reviewed_checkout_rejects_skip_worktree_or_non_normal_index_flags(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    git_path, git_sha = _git_authority(tmp_path)

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
            git_executable=git_path,
            git_executable_sha256=git_sha,
            environment={"PATH": "hostile"},
            command_runner=runner,
        )


def test_reviewed_one_shot_argv_is_isolated_and_binds_git_authority(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    script = repo / "scripts" / "run_r002f_one_shot_production_qualification.py"
    script.write_text("# stub\n", encoding="utf-8")
    python_exe = tmp_path / ("python.exe" if os.name == "nt" else "python")
    python_exe.write_bytes(b"python")
    git_path, git_sha = _git_authority(tmp_path)
    component = [
        "path-controlled-python",
        str(script),
        "--repo-root",
        str(repo),
        "--runner-source-commit",
        EXPECTED_COMMIT,
        "--instance-id",
        "instance-1",
    ]
    argv = reviewed_one_shot_argv(
        component,
        expected_commit=EXPECTED_COMMIT,
        repo_root=repo,
        python_executable=python_exe,
        git_executable=git_path,
        git_executable_sha256=git_sha,
    )
    assert argv[:4] == [str(python_exe.absolute()), "-I", "-X", "utf8"]
    assert argv[4] == str(script.absolute())
    git_index = argv.index("--git-executable")
    assert argv[git_index + 1] == str(git_path)
    sha_index = argv.index("--git-executable-sha256")
    assert argv[sha_index + 1] == git_sha


def test_reviewed_wrapper_binds_external_commit_git_and_isolated_command(
    tmp_path: Path,
) -> None:
    request = _request(tmp_path)
    request.repo_root.mkdir()
    (request.repo_root / "scripts").mkdir()
    script = request.repo_root / "scripts" / "run_r002f_one_shot_production_qualification.py"
    script.write_text("# stub\n", encoding="utf-8")
    proof_parent = tmp_path / "proofs"
    proof_parent.mkdir()
    final_proof = proof_parent / "reviewed.json"
    git_path, git_sha = _git_authority(tmp_path)
    python_exe = tmp_path / ("python.exe" if os.name == "nt" else "python")
    python_exe.write_bytes(b"python")
    checkout_calls: list[tuple[str, str]] = []

    def checkout_validator(
        repo_root,
        expected_commit,
        *,
        git_executable,
        git_executable_sha256,
        environment,
    ):  # type: ignore[no-untyped-def]
        assert repo_root == request.repo_root.absolute()
        assert expected_commit == EXPECTED_COMMIT
        assert git_executable == git_path
        assert git_executable_sha256 == git_sha
        assert "GIT_DIR" not in environment
        checkout_calls.append((expected_commit, git_executable_sha256))

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
                "path-python",
                str(script),
                "--repo-root",
                str(request.repo_root),
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
        git_executable=git_path,
        git_executable_sha256=git_sha,
        python_executable=python_exe,
        environment={"PATH": "hostile", "GIT_DIR": "evil"},
        checkout_validator=checkout_validator,
        component_runner=component_runner,
    )
    assert checkout_calls == [(EXPECTED_COMMIT, git_sha), (EXPECTED_COMMIT, git_sha)]
    assert result["status"] == "READY_FOR_REVIEWED_ONE_SHOT_EXECUTION"
    assert result["reviewed_git_executable_sha256"] == git_sha
    assert result["reviewed_git_executable_pinned_for_checkout"] is True
    argv = result["one_shot_argv"]
    assert isinstance(argv, list)
    assert argv[:4] == [str(python_exe.absolute()), "-I", "-X", "utf8"]
    assert result["python_isolated_bootstrap_required"] is True


def test_production_entrypoints_refuse_non_isolated_python_before_project_import(
    tmp_path: Path,
) -> None:
    repo = Path(__file__).resolve().parents[1]
    malicious_root = tmp_path / "malicious"
    package = malicious_root / "hms_gpt_vps"
    package.mkdir(parents=True)
    marker = tmp_path / "malicious-imported.txt"
    (package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(malicious_root)
    for relative in (
        "scripts/preflight_r002f_reviewed_one_shot_production_qualification.py",
        "scripts/run_r002f_one_shot_production_qualification.py",
    ):
        completed = subprocess.run(
            [sys.executable, str(repo / relative), "--repo-root", str(repo)],
            cwd=str(repo),
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30.0,
        )
        assert completed.returncode != 0
        assert "Python -I" in (completed.stdout + completed.stderr)
        assert not marker.exists()


def test_isolated_entrypoints_ignore_hostile_pythonpath_on_help(tmp_path: Path) -> None:
    repo = Path(__file__).resolve().parents[1]
    malicious_root = tmp_path / "malicious"
    package = malicious_root / "hms_gpt_vps"
    package.mkdir(parents=True)
    marker = tmp_path / "malicious-imported.txt"
    (package / "__init__.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = str(malicious_root)
    for relative in (
        "scripts/preflight_r002f_reviewed_one_shot_production_qualification.py",
        "scripts/run_r002f_one_shot_production_qualification.py",
    ):
        completed = subprocess.run(
            [
                sys.executable,
                "-I",
                str(repo / relative),
                "--repo-root",
                str(repo),
                "--help",
            ],
            cwd=str(repo),
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=30.0,
        )
        assert completed.returncode == 0, completed.stderr
        assert not marker.exists()
