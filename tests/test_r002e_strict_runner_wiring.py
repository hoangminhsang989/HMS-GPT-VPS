from pathlib import Path


RUNNER = Path(__file__).resolve().parents[1] / "scripts" / "qualify_managed_hyperv_agent.py"


def test_production_runner_publishes_only_strict_managed_hyperv_proof() -> None:
    source = RUNNER.read_text(encoding="utf-8")

    assert "qualify_managed_hyperv_agent_strict" in source
    assert "proof_payload = qualify_managed_hyperv_agent_strict(" in source
    assert "from hms_gpt_vps.managed_hyperv_agent_qualification import qualify_managed_hyperv_agent" not in source
    assert "proof = qualify_managed_hyperv_agent(" not in source
