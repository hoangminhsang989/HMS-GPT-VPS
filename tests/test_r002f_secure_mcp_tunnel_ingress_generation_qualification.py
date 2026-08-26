from __future__ import annotations

import pytest

import hms_gpt_vps.secure_mcp_tunnel_ingress_generation_qualification as module


GENERATION = "a" * 32


def evidence(**overrides):
    value = {
        "ready": True,
        "health_attempt_path": (
            r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-"
            + GENERATION
        ),
        "health_url_path": (
            r"C:\ProgramData\HMS-GPT-VPS\Bridge\runtime\tunnel-health\attempt-"
            + GENERATION
            + r"\health-url.txt"
        ),
        "tunnel_process_id": 5252,
    }
    value.update(overrides)
    return value


def test_extracts_exact_generation_from_validated_native_attempt():
    assert module.extract_mcp_ingress_generation_from_native_evidence(evidence()) == GENERATION


@pytest.mark.parametrize(
    "patch",
    [
        {"ready": False},
        {"health_attempt_path": ""},
        {"health_attempt_path": r"C:\x\attempt-" + "A" * 32},
        {"health_attempt_path": r"C:\x\wrong-" + GENERATION},
        {"health_attempt_path": r"C:\x\attempt-" + "a" * 31},
        {"health_url_path": r"C:\x\other.txt"},
    ],
)
def test_malformed_or_drifted_generation_evidence_fails_closed(patch):
    with pytest.raises(module.SecureMcpTunnelIngressGenerationQualificationError):
        module.extract_mcp_ingress_generation_from_native_evidence(evidence(**patch))


def test_wrapper_calls_exact_native_qualifier_and_adds_only_generation(monkeypatch):
    base = evidence(service_sid="S-1-5-80-1", service_process_id=4242)
    calls = []
    monkeypatch.setattr(
        module,
        "qualify_running_secure_mcp_tunnel",
        lambda **kwargs: calls.append(kwargs) or dict(base),
    )
    result = module.qualify_running_secure_mcp_tunnel_with_ingress_generation(
        service_sid="S-1-5-80-1",
        service_process_id=4242,
    )
    assert calls == [{"service_sid": "S-1-5-80-1", "service_process_id": 4242}]
    assert result == {**base, "mcp_ingress_generation": GENERATION}
    assert base.get("mcp_ingress_generation") is None


def test_wrapper_rejects_preexisting_generation_field(monkeypatch):
    monkeypatch.setattr(
        module,
        "qualify_running_secure_mcp_tunnel",
        lambda **kwargs: evidence(mcp_ingress_generation=GENERATION),
    )
    with pytest.raises(
        module.SecureMcpTunnelIngressGenerationQualificationError,
        match="unexpectedly already contains",
    ):
        module.qualify_running_secure_mcp_tunnel_with_ingress_generation(
            service_sid="S-1-5-80-1",
            service_process_id=4242,
        )
