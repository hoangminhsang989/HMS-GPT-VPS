from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hms_gpt_vps import r002f_production_proof_gate as gate


def _digest(seed: bytes) -> str:
    return hashlib.sha256(seed).hexdigest()


def _binding_inputs() -> tuple[dict[str, object], ...]:
    managed = {
        "instance_id": "instance-1",
        "vm_id": "11111111-2222-3333-4444-555555555555",
        "device_id": "device-1",
        "health_boot_id": "boot-1",
    }
    tunnel_sha = _digest(b"tunnel")
    activation = {
        "vm_id": "11111111-2222-3333-4444-555555555555",
        "tunnel_executable_sha256": tunnel_sha,
    }
    transport = {
        "agent_device_id": "device-1",
        "agent_boot_id": "boot-1",
        "tunnel_executable_sha256": tunnel_sha,
    }
    openai = {
        "instance_id": "instance-1",
        "source_commit": "a" * 40,
        "tunnel_executable_sha256": tunnel_sha,
    }
    return managed, activation, transport, openai


def test_bind_production_proofs_keeps_final_user_origin_and_full_flow_false() -> None:
    managed, activation, transport, openai = _binding_inputs()
    proof = gate.bind_r002f_production_proofs(
        managed=managed,
        activation=activation,
        transport=transport,
        openai=openai,
        managed_proof_sha256=_digest(b"managed"),
        activation_proof_sha256=_digest(b"activation"),
        transport_proof_sha256=_digest(b"transport"),
        openai_proof_sha256=_digest(b"openai"),
    )
    assert proof["cross_proof_identity_binding_proven"] is True
    assert proof["hyperv_guest_proven"] is True
    assert proof["authenticated_agent_transport_proven"] is True
    assert proof["openai_control_plane_origin_proven"] is True
    assert proof["chatgpt_ui_origin_proven"] is False
    assert proof["chatgpt_app_oauth_client_proven"] is False
    assert proof["full_bridge_command_flow_proven"] is False
    assert proof["bootstrap_retired"] is False
    assert proof["pairing_ready"] is False


@pytest.mark.parametrize(
    ("which", "value"),
    (
        ("activation_vm", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        ("transport_device", "other-device"),
        ("openai_instance", "other-instance"),
        ("transport_boot", "other-boot"),
        ("openai_tunnel", _digest(b"other-tunnel")),
    ),
)
def test_bind_production_proofs_rejects_cross_identity_drift(
    which: str,
    value: str,
) -> None:
    managed, activation, transport, openai = _binding_inputs()
    if which == "activation_vm":
        activation["vm_id"] = value
    elif which == "transport_device":
        transport["agent_device_id"] = value
    elif which == "openai_instance":
        openai["instance_id"] = value
    elif which == "transport_boot":
        transport["agent_boot_id"] = value
    else:
        openai["tunnel_executable_sha256"] = value
    with pytest.raises(gate.R002FProductionProofGateError):
        gate.bind_r002f_production_proofs(
            managed=managed,
            activation=activation,
            transport=transport,
            openai=openai,
            managed_proof_sha256=_digest(b"managed"),
            activation_proof_sha256=_digest(b"activation"),
            transport_proof_sha256=_digest(b"transport"),
            openai_proof_sha256=_digest(b"openai"),
        )


def test_load_json_object_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "proof.json"
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")
    with pytest.raises(gate.R002FProductionProofGateError):
        gate._load_json_object(path, label="test proof")


def test_verify_bundle_publishes_only_after_component_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    managed_path = tmp_path / "managed.json"
    activation_path = tmp_path / "activation.json"
    transport_path = tmp_path / "transport.json"
    openai_path = tmp_path / "openai.json"
    output_path = tmp_path / "bundle.json"

    managed_path.write_text('{"kind":"managed"}\n', encoding="utf-8")
    activation_path.write_text('{"kind":"activation"}\n', encoding="utf-8")
    transport_path.write_text('{"kind":"transport"}\n', encoding="utf-8")
    openai_path.write_text('{"kind":"openai"}\n', encoding="utf-8")

    managed, activation, transport, openai = _binding_inputs()

    def fake_validated_bundle_inputs(**kwargs: object):
        assert set(kwargs) == {
            "managed_hyperv_proof",
            "composite_activation_proof",
            "agent_transport_proof",
            "openai_control_plane_proof",
        }
        return managed, activation, transport, openai

    monkeypatch.setattr(
        gate,
        "_validated_bundle_inputs",
        fake_validated_bundle_inputs,
    )
    proof = gate.verify_r002f_production_proof_bundle(
        managed_hyperv_proof_path=managed_path,
        composite_activation_proof_path=activation_path,
        agent_transport_proof_path=transport_path,
        openai_control_plane_proof_path=openai_path,
        output_proof_path=output_path,
    )
    assert output_path.is_file()
    persisted = json.loads(output_path.read_text(encoding="utf-8"))
    assert persisted == proof
    assert proof["cross_proof_identity_binding_proven"] is True


def test_verify_bundle_rejects_reused_input_output_path(tmp_path: Path) -> None:
    same = tmp_path / "same.json"
    with pytest.raises(gate.R002FProductionProofGateError):
        gate.verify_r002f_production_proof_bundle(
            managed_hyperv_proof_path=same,
            composite_activation_proof_path=tmp_path / "activation.json",
            agent_transport_proof_path=tmp_path / "transport.json",
            openai_control_plane_proof_path=tmp_path / "openai.json",
            output_proof_path=same,
        )
