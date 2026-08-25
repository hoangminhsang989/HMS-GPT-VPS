from __future__ import annotations

from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import hms_gpt_vps.bridge_agent_transport_qualification as mod


def _presence_db(tmp_path: Path) -> Path:
    path = tmp_path / "agent-presence.sqlite3"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TABLE agent_presence (
                instance_id TEXT PRIMARY KEY NOT NULL,
                device_id TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                connection_epoch INTEGER NOT NULL,
                first_seen_unix REAL NOT NULL,
                last_seen_unix REAL NOT NULL
            ) WITHOUT ROWID
            """
        )
        connection.execute(
            "INSERT INTO agent_presence VALUES (?, ?, ?, ?, ?, ?)",
            ("HMS-VPS-1", "device-1", "boot-1", 7, 100.0, 101.0),
        )
        connection.commit()
    finally:
        connection.close()
    return path


def test_presence_observer_is_read_only_and_parses_exact_row(tmp_path: Path):
    path = _presence_db(tmp_path)
    before = path.read_bytes()
    presence = mod._read_presence_read_only(path, "HMS-VPS-1")
    assert presence is not None
    assert presence.device_id == "device-1"
    assert presence.boot_id == "boot-1"
    assert presence.connection_epoch == 7
    assert path.read_bytes() == before


def test_guest_observation_script_uses_loopback_health_and_fixed_config_only():
    script = mod.build_guest_hms_agent_observation_script()
    assert "HMSAgent" in script
    assert "ProgramData" in script
    assert "agent-runtime.json" in script
    assert "http://127.0.0.1:" in script
    assert "/healthz" in script
    assert "Start-Service" not in script
    assert "Stop-Service" not in script


def test_heartbeat_stability_requires_same_generation_and_new_activity(monkeypatch):
    initial = mod._Presence("i", "d", "b", 4, 10.0, 11.0)
    current = mod._Presence("i", "d", "b", 4, 10.0, 50.0)
    monkeypatch.setattr(mod, "_read_presence_read_only", lambda *a, **k: current)
    sleeps = []
    result = mod._wait_for_heartbeat_generation_stability(
        Path("/tmp/presence"),
        initial,
        margin_seconds=2.0,
        sleeper=lambda seconds: sleeps.append(seconds),
    )
    assert result == current
    assert sleeps == [mod._HEARTBEAT_INTERVAL_SECONDS + 2.0]


def test_transport_qualification_always_stops_and_keeps_pairing_false(monkeypatch):
    class FakeConfig:
        instance_id = "HMS-VPS-1"
        vm_id = "12345678-1234-1234-1234-123456789abc"
        vm_name = "HMS-VPS-1"
        runtime_root = "/runtime"
        tls_port = 9443

        def validate(self):
            return None

        def to_runtime_config(self, sid):
            return SimpleNamespace(
                secret_storage=object(),
                tls=SimpleNamespace(
                    firewall=SimpleNamespace(
                        network=SimpleNamespace(gateway="172.29.240.1"),
                        port=9443,
                    )
                ),
            )

    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", FakeConfig)
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: "S-1-5-80-1-2-3-4-5")
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", FakeConfig)
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: object())
    identity = {
        "service_sid": "S-1-5-80-1-2-3-4-5",
        "service_state": "Stopped",
        "service_start_mode": "Manual",
    }
    monkeypatch.setattr(mod, "prove_hms_bridge_provisioning_identity", lambda: identity)
    guest = {"health_boot_id": "boot-1", "process_id": 4321}
    monkeypatch.setattr(mod, "_observe_guest_agent", lambda *a, **k: dict(guest))
    monkeypatch.setattr(
        mod,
        "start_hms_bridge_for_qualification",
        lambda *a, **k: {"process_id": 777},
    )
    stops = []
    monkeypatch.setattr(
        mod,
        "stop_hms_bridge_after_qualification",
        lambda *a, **k: stops.append(True) or {"ready": True},
    )
    hello = mod._Presence("HMS-VPS-1", "device-1", "boot-1", 9, 1.0, 2.0)
    beat = mod._Presence("HMS-VPS-1", "device-1", "boot-1", 9, 1.0, 40.0)
    monkeypatch.setattr(mod, "_wait_for_authenticated_hello", lambda *a, **k: hello)
    monkeypatch.setattr(mod, "_wait_for_heartbeat_generation_stability", lambda *a, **k: beat)
    monkeypatch.setattr(
        mod,
        "_enqueue_read_only_git_status",
        lambda *a, **k: (object(), "r002fqual-test"),
    )
    result = SimpleNamespace(
        outcome="ok",
        instance_id="HMS-VPS-1",
        request_id="r002fqual-test",
    )
    monkeypatch.setattr(mod, "_wait_for_result", lambda *a, **k: result)
    monkeypatch.setattr(mod, "_read_presence_read_only", lambda *a, **k: beat)

    request = mod.BridgeAgentTransportQualificationRequest(
        guest_credential=mod.PowerShellDirectCredential("Admin", "secret"),
    )
    evidence = mod.qualify_authenticated_agent_transport(request)

    assert stops == [True]
    assert evidence["authenticated_hello_proven"] is True
    assert evidence["authenticated_heartbeat_proven"] is True
    assert evidence["authenticated_poll_proven"] is True
    assert evidence["authenticated_result_proven"] is True
    assert evidence["authenticated_agent_transport_proven"] is True
    assert evidence["full_bridge_command_flow_proven"] is False
    assert evidence["pairing_ready"] is False
    assert evidence["service_state"] == "Stopped"


def test_transport_qualification_failure_still_stops(monkeypatch):
    class FakeConfig:
        instance_id = "HMS-VPS-1"
        vm_id = "12345678-1234-1234-1234-123456789abc"
        vm_name = "HMS-VPS-1"
        runtime_root = "/runtime"
        tls_port = 9443

        def validate(self):
            return None

        def to_runtime_config(self, sid):
            return SimpleNamespace()

    monkeypatch.setattr(mod, "BridgeServiceRuntimeConfig", FakeConfig)
    monkeypatch.setattr(mod, "derive_hms_bridge_service_sid", lambda: "S-1-5-80-1-2-3-4-5")
    monkeypatch.setattr(mod, "load_protected_bridge_service_runtime_config", FakeConfig)
    monkeypatch.setattr(mod, "_load_and_verify_package", lambda: object())
    monkeypatch.setattr(
        mod,
        "prove_hms_bridge_provisioning_identity",
        lambda: {
            "service_sid": "S-1-5-80-1-2-3-4-5",
            "service_state": "Stopped",
            "service_start_mode": "Manual",
        },
    )
    monkeypatch.setattr(
        mod,
        "_observe_guest_agent",
        lambda *a, **k: {"health_boot_id": "boot-1", "process_id": 4321},
    )
    monkeypatch.setattr(
        mod,
        "start_hms_bridge_for_qualification",
        lambda *a, **k: {"process_id": 777},
    )
    stops = []
    monkeypatch.setattr(
        mod,
        "stop_hms_bridge_after_qualification",
        lambda *a, **k: stops.append(True) or {"ready": True},
    )
    monkeypatch.setattr(
        mod,
        "_wait_for_authenticated_hello",
        lambda *a, **k: (_ for _ in ()).throw(
            mod.BridgeAgentTransportQualificationError("hello failed")
        ),
    )

    request = mod.BridgeAgentTransportQualificationRequest(
        guest_credential=mod.PowerShellDirectCredential("Admin", "secret"),
    )
    with pytest.raises(mod.BridgeAgentTransportQualificationError, match="hello failed"):
        mod.qualify_authenticated_agent_transport(request)
    assert stops == [True]
