from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

import pytest


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "qualify_managed_hyperv_agent.py"


def load_runner():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("r002e_hyperv_qualification_runner", SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runner_cli_never_accepts_bootstrap_password_or_device_secret() -> None:
    runner = load_runner()
    parser = runner.build_parser()
    options = {
        option
        for action in parser._actions  # type: ignore[attr-defined]
        for option in action.option_strings
    }

    assert "--bootstrap-password" not in options
    assert "--password" not in options
    assert "--device-secret" not in options
    assert "--device-secret-b64" not in options
    assert "--bridge-device-credential" in options


def test_bootstrap_credential_is_loaded_from_env_then_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = load_runner()
    monkeypatch.setenv(runner.BOOTSTRAP_USERNAME_ENV, "hmsbootstrap")
    monkeypatch.setenv(runner.BOOTSTRAP_PASSWORD_ENV, "super-secret-bootstrap-password")

    credential = runner._load_bootstrap_credential()

    assert credential.username == "hmsbootstrap"
    assert credential.password == "super-secret-bootstrap-password"
    assert runner.BOOTSTRAP_USERNAME_ENV not in os.environ
    assert runner.BOOTSTRAP_PASSWORD_ENV not in os.environ
    assert "super-secret-bootstrap-password" not in repr(credential)


def test_existing_proof_path_is_rejected(tmp_path: Path) -> None:
    runner = load_runner()
    proof = tmp_path / "proof.json"
    proof.write_text("stale-proof", encoding="utf-8")

    with pytest.raises(ValueError, match="must be absent"):
        runner._new_proof_path(str(proof))


def test_production_proof_writer_is_create_only(tmp_path: Path) -> None:
    runner = load_runner()
    proof = tmp_path / "proof.json"
    payload = {
        "qualification": "managed_hyperv_guest_agent",
        "hyperv_guest_proven": True,
        "full_bridge_command_flow_proven": False,
    }

    runner._write_proof_create_only(proof, payload)
    assert json.loads(proof.read_text(encoding="utf-8")) == payload

    with pytest.raises(ValueError, match="must be absent"):
        runner._write_proof_create_only(proof, {"replacement": True})
    assert json.loads(proof.read_text(encoding="utf-8")) == payload


def test_authority_file_rejects_symlinked_parent(tmp_path: Path) -> None:
    runner = load_runner()
    real = tmp_path / "real"
    real.mkdir()
    target = real / "authority.json"
    target.write_text("{}", encoding="utf-8")
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation is unavailable: {exc}")

    with pytest.raises(ValueError, match="path chain"):
        runner._absolute_existing_file(str(linked / "authority.json"), "authority")
