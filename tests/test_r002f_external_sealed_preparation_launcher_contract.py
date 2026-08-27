from __future__ import annotations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "scripts" / "run_r002f_external_sealed_preparation_launcher.ps1"
DOC = ROOT / "docs" / "R002F_EXTERNAL_SEALED_PREPARATION_LAUNCHER.md"

def source() -> str:
    return LAUNCHER.read_text(encoding="utf-8")

def test_launcher_pins_exact_reviewed_stage0_child() -> None:
    text = source()
    assert "$stage0Sha='3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f'" in text
    assert "Open-Pin $stage0 'reviewed stage0 child'" in text
    assert "stage0 child bytes changed across execution" in text
    assert "[IO.FileShare]::Read" in text

def test_launcher_has_no_raw_remaining_arguments_channel() -> None:
    text = source()
    assert "ValueFromRemainingArguments" not in text
    assert "PreflightArgs" not in text
    assert "--execution-root" not in " ".join(line for line in text.splitlines() if "Add-Optional $forward" in line)
    assert "Add-Optional $forward '--external-timeout'" in text
    assert "optional preflight value must not begin with option prefix" in text

def test_launcher_independently_checks_preflight_type_exactness() -> None:
    text = source()
    assert "Bool-Is $po.PSObject.Properties[$name].Value $true" in text
    assert "Bool-Is $po.PSObject.Properties[$name].Value $false" in text
    assert "preflight schema differs" in text
    assert "preflight system directory differs" in text
    assert "preflight manifest digest differs" in text

def test_launcher_cross_binds_stage0_to_actual_preflight_proof() -> None:
    text = source()
    assert "stage0/preflight proof digest binding differs" in text
    assert "stage0_external_sha256" in text
    assert "stage0_observed_sha256" in text
    assert "external_preexecution_pin_self_proven" in text

def test_launcher_never_claims_live_execution() -> None:
    text = source()
    assert "execution_started=$false" in text
    assert "hyperv_mutated=$false" in text
    assert "bridge_started=$false" in text
    assert "tunnel_started=$false" in text

def test_launcher_external_root_of_trust_remains_explicit() -> None:
    text = source()
    assert "launcher SHA-256 differs from external authority" in text
    assert "external_launcher_preexecution_pin_required=$true" in text
    assert "external_launcher_preexecution_pin_self_proven=$false" in text
    doc = DOC.read_text(encoding="utf-8")
    assert "must pin the launcher SHA-256 before process creation" in doc


def test_launcher_type_exactly_validates_stage0_proof_too() -> None:
    text = source()
    assert "Props $so @('schema_version','qualification','status','ready','reviewed_commit'" in text
    assert "stage0 proof schema differs" in text
    assert "stage0 proof preflight exit type differs" in text
    assert "stage0 proof manifest digest differs" in text
    assert "stage0 proof path binding differs" in text
    assert "project_tree_sealed','python_runtime_sealed','git_runtime_sealed','external_preexecution_pin_required" in text


def test_launcher_sanitizes_host_search_path_before_any_pinned_child_or_json_parse() -> None:
    text = source()
    sanitize = text.index("[Environment]::SetEnvironmentVariable('PSModulePath'")
    first_pin = text.index("$launcherPin=Open-Pin")
    first_proof_read = text.index("$p=Read-Proof")
    assert sanitize < first_pin < first_proof_read
    assert "Get-Item" not in text
    assert "[IO.File]::GetAttributes($current)" in text
