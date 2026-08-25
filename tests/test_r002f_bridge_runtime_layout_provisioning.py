from __future__ import annotations

from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_runtime_layout_provisioning as mod


SID = "S-1-5-80-1-2-3-4-5"


class Config:
    runtime_root = r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime"
    provision_state_path = (
        r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\provision-state.json"
    )

    def validate(self):
        return None


def test_authority_rejects_runtime_root_drift(monkeypatch):
    config = Config()
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    mod.validate_bridge_runtime_layout_authority(config)
    config.runtime_root = r"C:\Temp\runtime"
    with pytest.raises(mod.BridgeRuntimeLayoutProvisioningError):
        mod.validate_bridge_runtime_layout_authority(config)


def test_script_requires_stopped_manual_service_and_inheritable_modify(monkeypatch):
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    script = mod.build_bridge_runtime_layout_provisioning_script(
        Config(),
        expected_service_sid=SID,
        reconcile=True,
    )
    assert "must remain Manual" in script
    assert "must remain Stopped" in script
    assert "ContainerInherit" in script
    assert "ObjectInherit" in script
    assert "FileSystemRights]::Modify" in script
    assert "principal-bindings" in script


def test_provision_is_identity_and_observer_proof_sandwiched(monkeypatch):
    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", Config)
    calls = []
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: calls.append("identity") or {"service_sid": SID},
    )
    monkeypatch.setattr(
        mod,
        "_run_layout",
        lambda config, **kwargs: calls.append(("layout", kwargs["reconcile"]))
        or {
            "changed": kwargs["reconcile"],
            "runtime_root": config.runtime_root,
            "db_dir": config.runtime_root + r"\db",
            "secrets_dir": config.runtime_root + r"\secrets",
            "locks_dir": config.runtime_root + r"\locks",
            "principal_bindings_dir": config.runtime_root
            + r"\secrets\principal-bindings",
        },
    )
    monkeypatch.setattr(
        mod.BridgeRuntimeLayout,
        "prepare",
        lambda path: SimpleNamespace(
            root=path,
            db_dir=path / "db",
            secrets_dir=path / "secrets",
            locks_dir=path / "locks",
            principal_bindings_dir=path / "secrets" / "principal-bindings",
        ),
    )
    monkeypatch.setattr(mod, "_same_windows_path", lambda a, b: True)

    result = mod.provision_bridge_runtime_layout(Config())

    assert calls == [
        "identity",
        ("layout", True),
        ("layout", False),
        "identity",
    ]
    assert result["code_layout_prepared"] is True
    assert result["post_identity_proven"] is True
