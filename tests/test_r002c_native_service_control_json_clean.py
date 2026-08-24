from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_qualification_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "qualify_native_agent_service.py"
    spec = importlib.util.spec_from_file_location("hms_r002c_native_qualification", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load native qualification script for regression test")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_service_control_suppresses_warning_streams_and_success_output(
    monkeypatch,
) -> None:
    qualification = _load_qualification_module()
    scripts: list[str] = []

    def fake_run_powershell_json(
        script: str,
        *,
        timeout_seconds: int,
        **_kwargs: object,
    ) -> dict[str, object]:
        scripts.append(script)
        if "sc.exe delete" in script:
            return {"deleted": True}
        if "Start-Service" in script:
            return {"running": True}
        return {"stopped": True}

    monkeypatch.setattr(qualification, "run_powershell_json", fake_run_powershell_json)

    qualification._stop_service("HMSAgent")
    qualification._start_service("HMSAgent")
    qualification._delete_service_if_present("HMSAgent")

    assert len(scripts) == 3
    stop_script, start_script, delete_script = scripts

    assert "$null = Stop-Service" in stop_script
    assert "-WarningAction SilentlyContinue" in stop_script
    assert "$null = $service.WaitForStatus(" in stop_script
    assert "$null = $service.Refresh()" in stop_script
    assert "$null = $service.Dispose()" in stop_script

    assert "$null = Start-Service" in start_script
    assert "-WarningAction SilentlyContinue" in start_script
    assert "$null = $service.WaitForStatus(" in start_script
    assert "$null = $service.Refresh()" in start_script
    assert "$null = $service.Dispose()" in start_script

    assert "$null = Stop-Service" in delete_script
    assert "-WarningAction SilentlyContinue" in delete_script
    assert "$null = $service.WaitForStatus(" in delete_script
    assert "sc.exe delete" in delete_script
