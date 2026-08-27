from __future__ import annotations

from pathlib import Path

from hms_gpt_vps.r002f_sealed_runtime_authority import sealed_child_environment


ROOT = Path(__file__).resolve().parents[1]


def test_sealed_environment_discards_controls_and_bounds_search_paths(
    tmp_path: Path,
) -> None:
    system = tmp_path / "System32"
    system.mkdir()
    git_dir = tmp_path / "git" / "cmd"
    git_dir.mkdir(parents=True)
    git = git_dir / "git.exe"
    git.write_bytes(b"git")
    import os

    powershell_dir = system / "WindowsPowerShell" / "v1.0"
    powershell_dir.mkdir(parents=True)
    env = sealed_child_environment(
        {
            "PATH": "attacker",
            "PYTHONPATH": "attacker",
            "GIT_DIR": "attacker",
            "PSModulePath": "attacker",
            "KEEP": "1",
        },
        system_directory=system,
        git_executable=git,
    )
    assert env["PATH"].split(os.pathsep) == [
        str(git_dir.absolute()),
        str(powershell_dir.absolute()),
        str(system.absolute()),
    ]
    assert "PYTHONPATH" not in env
    assert "GIT_DIR" not in env
    assert env["PSModulePath"] == str(
        system / "WindowsPowerShell" / "v1.0" / "Modules"
    )
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["KEEP"] == "1"


def test_sealed_preflight_replaces_mutable_command_surface() -> None:
    command = (
        ROOT / "src" / "hms_gpt_vps" / "r002f_sealed_preflight_command.py"
    ).read_text(encoding="utf-8")
    entrypoint = (
        ROOT / "src" / "hms_gpt_vps" / "r002f_sealed_preflight_entrypoint.py"
    ).read_text(encoding="utf-8")
    assert 'remove_pair(tail, "--repo-root")' in command
    assert "run_r002f_sealed_one_shot_production_qualification.py" in command
    assert "--execution-manifest-sha256" in command
    assert "--python-runtime-manifest-sha256" in command
    assert "runner is not None and runner != reviewed_commit" in entrypoint
    assert "ready and runner != reviewed_commit" in entrypoint


def test_live_entrypoint_uses_sealed_root_and_python() -> None:
    source = (
        ROOT / "src" / "hms_gpt_vps" / "r002f_sealed_one_shot_entrypoint.py"
    ).read_text(encoding="utf-8")
    assert "repo_root=authority.execution_root" in source
    assert "python_executable=str(authority.python_executable)" in source
    assert "checkout_validator=sealed_validator" in source
    assert '"git_runtime_required_for_live_execution": False' in source
