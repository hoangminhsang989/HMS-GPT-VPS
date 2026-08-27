from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STAGE0 = ROOT / "scripts" / "run_r002f_external_sealed_preparation_stage0.ps1"
DOC = ROOT / "docs" / "R002F_EXTERNAL_SEALED_PREPARATION_STAGE0.md"


def source() -> str:
    return STAGE0.read_text(encoding="utf-8")


def test_stage0_never_imports_project_python_before_seal() -> None:
    text = source()
    assert "hms_gpt_vps" not in text
    assert "ConvertFrom-Json" in text
    launch = text.index("$stdout=@(& $pythonEntry")
    assert text.index("Copy-ManifestTree $ProjectSourceRoot") < launch
    assert text.index("Seal-Tree $execution") < launch
    assert text.index("Verify-SealedAcls $execution") < launch
    assert text.index("Verify-ManifestTree $gitRoot") < launch


def test_stage0_preserves_external_root_of_trust_boundary() -> None:
    text = source()
    assert "stage0_external_sha256=$Stage0ExternalSha256" in text
    assert "stage0_observed_sha256=(Stream-Sha256 $stage0Pin)" in text
    assert "external_preexecution_pin_required=$true" in text
    assert "external_preexecution_pin_self_proven=$false" in text
    assert "Open-PinnedRead $stage0 'stage-0 artifact'" in text


def test_stage0_closes_runtime_and_argument_substitution_boundaries() -> None:
    text = source()
    assert "Python runtime must be self-contained and must not contain pyvenv.cfg" in text
    assert "Git runtime shadows a host executable" in text
    assert "Assert-PreflightArgs $PreflightArgs" in text
    assert "preflight args attempt to override stage-0 sealed authority" in text
    assert "preflight args contain duplicate option" in text
    assert "sealed destination roots must be distinct" in text
    assert "authority parent must be separate from mutable/source roots" in text
    assert "stage-0 artifact must be a direct child of authority parent" in text
    assert "manifest files must be direct children of authority parent" in text
    assert "Python runtime must be self-contained and must not contain pyvenv.cfg" in text


def test_stage0_sanitizes_host_search_paths_before_acl_cmdlets_execute() -> None:
    text = source()
    env = text.index("[Environment]::SetEnvironmentVariable('PSModulePath'")
    parent_acl_call = text.index("Require-PreparationParentAcl $authority")
    assert env < parent_acl_call
    assert "[Environment]::SystemDirectory" in text
    assert "'WindowsPowerShell','v1.0'" in text


def test_stage0_is_create_only_and_preserves_partial_forensics() -> None:
    text = source()
    assert "[IO.FileMode]::CreateNew" in text
    assert "partial_artifacts_preserved=$true" in text
    assert "Remove-Item -Recurse" not in text
    assert "execution_started=$false" in text
    assert "hyperv_mutated=$false" in text


def test_external_launcher_contract_holds_stage0_handle_across_child() -> None:
    text = DOC.read_text(encoding="utf-8")
    assert "[IO.FileShare]::Read" in text
    assert "$handle.Dispose()" in text
    assert "& $powershell" in text
    assert "-NoProfile" in text
    assert "external_preexecution_pin_self_proven=false" in text


def test_stage0_requires_and_binds_real_sealed_preflight_proof() -> None:
    text = source()
    launch = text.index("$stdout=@(& $pythonEntry")
    proof_read = text.index("Read-PinnedUtf8JsonObserved $preflightProof")
    assert launch < proof_read
    assert "R002F_SEALED_EXECUTION_PREFLIGHT" in text
    assert "sealed preflight proof ready/exit binding differs" in text
    assert "preflight_proof_sha256=$preflightProofSha256" in text
