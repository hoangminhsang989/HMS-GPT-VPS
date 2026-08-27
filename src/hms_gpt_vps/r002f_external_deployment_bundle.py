from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PureWindowsPath

from .r002f_external_deployment_bundle_types import (
    LAUNCHER_FILENAME,
    PATH_FIELDS,
    REVIEWED_LAUNCHER_SHA256,
    REVIEWED_STAGE0_SHA256,
    STAGE0_FILENAME,
    PinnedArtifact,
    PreflightAuthority,
    R002FExternalDeploymentBundleError,
    SealedTreeAuthority,
    direct_child,
    same,
    sha1,
    strict_object,
    windows_absolute,
    within,
)

SCHEMA_VERSION = 1
QUALIFICATION = "R002F_EXTERNAL_DEPLOYMENT_AUTHORITY_BUNDLE"
MAX_BUNDLE_BYTES = 256 * 1024
MAX_RENDERED_COMMAND_CHARS = 30000


@dataclass(frozen=True)
class R002FExternalDeploymentAuthorityBundle:
    reviewed_commit: str
    authority_parent: str
    launcher: PinnedArtifact
    stage0: PinnedArtifact
    project: SealedTreeAuthority
    python_runtime: SealedTreeAuthority
    git_runtime: SealedTreeAuthority
    repo_evidence_root: str
    preflight_proof_path: str
    stage0_proof_path: str
    launcher_proof_path: str
    preflight: PreflightAuthority

    def validate(self) -> None:
        sha1(self.reviewed_commit, "reviewed commit")
        authority = windows_absolute(self.authority_parent, "authority_parent")
        if same(str(PureWindowsPath(authority).parent), authority):
            raise R002FExternalDeploymentBundleError(
                "authority_parent must not be a filesystem root"
            )
        self.launcher.validate(label="launcher", filename=LAUNCHER_FILENAME)
        self.stage0.validate(label="stage0", filename=STAGE0_FILENAME)
        if self.launcher.sha256 != REVIEWED_LAUNCHER_SHA256:
            raise R002FExternalDeploymentBundleError(
                "launcher SHA-256 differs from reviewed V2 authority"
            )
        if self.stage0.sha256 != REVIEWED_STAGE0_SHA256:
            raise R002FExternalDeploymentBundleError(
                "stage0 SHA-256 differs from reviewed authority"
            )
        if not direct_child(self.launcher.path, authority):
            raise R002FExternalDeploymentBundleError(
                "launcher must be a direct child of authority_parent"
            )
        if not direct_child(self.stage0.path, authority):
            raise R002FExternalDeploymentBundleError(
                "stage0 must be a direct child of authority_parent"
            )

        groups = (
            ("project", self.project),
            ("python_runtime", self.python_runtime),
            ("git_runtime", self.git_runtime),
        )
        for label, item in groups:
            item.validate(label=label)
            if not direct_child(item.manifest_path, authority):
                raise R002FExternalDeploymentBundleError(
                    f"{label} manifest must be a direct child of authority_parent"
                )
            if not direct_child(item.destination_root, authority):
                raise R002FExternalDeploymentBundleError(
                    f"{label} destination must be a direct child of authority_parent"
                )

        destinations = tuple(item.destination_root for _, item in groups)
        for index, left in enumerate(destinations):
            for right in destinations[index + 1 :]:
                if same(left, right) or within(left, right) or within(right, left):
                    raise R002FExternalDeploymentBundleError(
                        "sealed destination roots must be distinct and non-nested"
                    )

        repo_evidence = windows_absolute(
            self.repo_evidence_root, "repo_evidence_root"
        )
        sources = tuple(item.source_root for _, item in groups) + (repo_evidence,)
        for source in sources:
            if (
                same(source, authority)
                or within(source, authority)
                or within(authority, source)
            ):
                raise R002FExternalDeploymentBundleError(
                    "authority_parent must be separate from mutable/source roots"
                )
            for destination in destinations:
                if (
                    same(source, destination)
                    or within(source, destination)
                    or within(destination, source)
                ):
                    raise R002FExternalDeploymentBundleError(
                        "source/evidence roots must be separate from "
                        "sealed destinations"
                    )

        proofs = (
            windows_absolute(self.preflight_proof_path, "preflight_proof_path"),
            windows_absolute(self.stage0_proof_path, "stage0_proof_path"),
            windows_absolute(self.launcher_proof_path, "launcher_proof_path"),
        )
        if len({str(PureWindowsPath(p)).casefold() for p in proofs}) != 3:
            raise R002FExternalDeploymentBundleError("proof paths must be distinct")
        if any(not direct_child(path, authority) for path in proofs):
            raise R002FExternalDeploymentBundleError(
                "proof paths must be direct children of authority_parent"
            )
        direct_authorities = (
            self.launcher.path,
            self.stage0.path,
            self.project.manifest_path,
            self.python_runtime.manifest_path,
            self.git_runtime.manifest_path,
            *destinations,
            *proofs,
        )
        if len(
            {str(PureWindowsPath(path)).casefold() for path in direct_authorities}
        ) != len(direct_authorities):
            raise R002FExternalDeploymentBundleError(
                "authority_parent direct-child paths must be unique"
            )

        self.preflight.validate()
        for path in tuple(
            getattr(self.preflight, name) for name in sorted(PATH_FIELDS)
        ):
            if (
                same(path, authority)
                or within(path, authority)
                or within(authority, path)
            ):
                raise R002FExternalDeploymentBundleError(
                    "preflight path authorities must be separate from "
                    "authority_parent"
                )
            for destination in destinations:
                if (
                    same(path, destination)
                    or within(path, destination)
                    or within(destination, path)
                ):
                    raise R002FExternalDeploymentBundleError(
                        "preflight path authorities must be separate from "
                        "sealed destinations"
                    )

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": SCHEMA_VERSION,
            "qualification": QUALIFICATION,
            "reviewed_commit": self.reviewed_commit,
            "authority_parent": self.authority_parent,
            "launcher": {
                "path": self.launcher.path,
                "sha256": self.launcher.sha256,
            },
            "stage0": {"path": self.stage0.path, "sha256": self.stage0.sha256},
            "project": self.project.to_dict(),
            "python_runtime": self.python_runtime.to_dict(),
            "git_runtime": self.git_runtime.to_dict(),
            "repo_evidence_root": self.repo_evidence_root,
            "preflight_proof_path": self.preflight_proof_path,
            "stage0_proof_path": self.stage0_proof_path,
            "launcher_proof_path": self.launcher_proof_path,
            "preflight": self.preflight.to_dict(),
        }

    def to_bytes(self) -> bytes:
        return (
            json.dumps(
                self.to_dict(),
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @classmethod
    def from_bytes(
        cls, data: bytes
    ) -> "R002FExternalDeploymentAuthorityBundle":
        if not isinstance(data, bytes) or not data or len(data) > MAX_BUNDLE_BYTES:
            raise R002FExternalDeploymentBundleError(
                "deployment bundle size is outside bounds"
            )

        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if key in result:
                    raise R002FExternalDeploymentBundleError(
                        "deployment bundle contains duplicate fields"
                    )
                result[key] = value
            return result

        try:
            raw = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=pairs,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    R002FExternalDeploymentBundleError(
                        f"deployment bundle contains non-finite value: {value}"
                    )
                ),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise R002FExternalDeploymentBundleError(
                "deployment bundle must be strict UTF-8 JSON"
            ) from exc

        names = frozenset(
            {
                "schema_version",
                "qualification",
                "reviewed_commit",
                "authority_parent",
                "launcher",
                "stage0",
                "project",
                "python_runtime",
                "git_runtime",
                "repo_evidence_root",
                "preflight_proof_path",
                "stage0_proof_path",
                "launcher_proof_path",
                "preflight",
            }
        )
        obj = strict_object(raw, names, "deployment bundle")
        if (
            type(obj.get("schema_version")) is not int
            or obj.get("schema_version") != SCHEMA_VERSION
        ):
            raise R002FExternalDeploymentBundleError(
                "deployment bundle schema_version differs"
            )
        if obj.get("qualification") != QUALIFICATION:
            raise R002FExternalDeploymentBundleError(
                "deployment bundle qualification differs"
            )
        texts = (
            "reviewed_commit",
            "authority_parent",
            "repo_evidence_root",
            "preflight_proof_path",
            "stage0_proof_path",
            "launcher_proof_path",
        )
        if any(not isinstance(obj.get(name), str) for name in texts):
            raise R002FExternalDeploymentBundleError(
                "deployment bundle text field types are invalid"
            )
        bundle = cls(
            reviewed_commit=obj["reviewed_commit"],
            authority_parent=obj["authority_parent"],
            launcher=PinnedArtifact.from_mapping(
                obj["launcher"], label="launcher"
            ),
            stage0=PinnedArtifact.from_mapping(obj["stage0"], label="stage0"),
            project=SealedTreeAuthority.from_mapping(
                obj["project"], label="project"
            ),
            python_runtime=SealedTreeAuthority.from_mapping(
                obj["python_runtime"], label="python_runtime"
            ),
            git_runtime=SealedTreeAuthority.from_mapping(
                obj["git_runtime"], label="git_runtime"
            ),
            repo_evidence_root=obj["repo_evidence_root"],
            preflight_proof_path=obj["preflight_proof_path"],
            stage0_proof_path=obj["stage0_proof_path"],
            launcher_proof_path=obj["launcher_proof_path"],
            preflight=PreflightAuthority.from_mapping(obj["preflight"]),
        )
        bundle.validate()
        return bundle


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def render_os_trusted_launcher_command(
    bundle: R002FExternalDeploymentAuthorityBundle,
) -> str:
    if not isinstance(bundle, R002FExternalDeploymentAuthorityBundle):
        raise TypeError("bundle must be R002FExternalDeploymentAuthorityBundle")
    bundle.validate()
    p = bundle.preflight
    args = [
        "-ReviewedCommit", bundle.reviewed_commit,
        "-ProjectSourceRoot", bundle.project.source_root,
        "-ProjectManifestPath", bundle.project.manifest_path,
        "-ProjectManifestSha256", bundle.project.manifest_sha256,
        "-PythonSourceRoot", bundle.python_runtime.source_root,
        "-PythonManifestPath", bundle.python_runtime.manifest_path,
        "-PythonManifestSha256", bundle.python_runtime.manifest_sha256,
        "-GitSourceRoot", bundle.git_runtime.source_root,
        "-GitManifestPath", bundle.git_runtime.manifest_path,
        "-GitManifestSha256", bundle.git_runtime.manifest_sha256,
        "-AuthorityParent", bundle.authority_parent,
        "-ExecutionRoot", bundle.project.destination_root,
        "-PythonRuntimeRoot", bundle.python_runtime.destination_root,
        "-GitRuntimeRoot", bundle.git_runtime.destination_root,
        "-RepoEvidenceRoot", bundle.repo_evidence_root,
        "-PreflightProofPath", bundle.preflight_proof_path,
        "-Stage0ProofPath", bundle.stage0_proof_path,
        "-LauncherProofPath", bundle.launcher_proof_path,
        "-RunDir", p.run_dir,
        "-PackageRoot", p.package_root,
        "-PackageManifest", p.package_manifest,
        "-RuntimeConfig", p.runtime_config,
        "-InstanceRegistry", p.instance_registry,
        "-InstanceRuntimeDir", p.instance_runtime_dir,
        "-BridgeDeviceCredential", p.bridge_device_credential,
        "-TrustRootCertificate", p.trust_root_certificate,
        "-ChallengeSourceCommit", p.challenge_source_commit,
        "-ChallengeWorkspacePath", p.challenge_workspace_path,
        "-ChallengeExpectedSha256", p.challenge_expected_sha256,
        "-MaxReconcileSteps", str(p.max_reconcile_steps),
        "-ExternalTimeout", format(float(p.external_timeout_seconds), ".17g"),
        "-StepTimeout", format(float(p.step_timeout_seconds), ".17g"),
    ]
    values = ",".join(_ps_literal(value) for value in args)
    command = (
        "$launcher=" + _ps_literal(bundle.launcher.path) + ";"
        "$expected=" + _ps_literal(bundle.launcher.sha256) + ";"
        "$handle=[IO.FileStream]::new($launcher,[IO.FileMode]::Open,"
        "[IO.FileAccess]::Read,[IO.FileShare]::Read);"
        "try{$h=[Security.Cryptography.SHA256]::Create();"
        "try{$observed=([BitConverter]::ToString($h.ComputeHash($handle)))."
        "Replace('-','').ToLowerInvariant()}finally{$h.Dispose();"
        "$handle.Position=0};"
        "if($observed -cne $expected){throw "
        "'launcher external SHA-256 mismatch'};"
        "$system=[Environment]::SystemDirectory;"
        "$powershell=[IO.Path]::Combine($system,'WindowsPowerShell',"
        "'v1.0','powershell.exe');"
        "if(-not[IO.File]::Exists($powershell)){throw "
        "'OS Windows PowerShell missing'};$code=255;"
        "$a=@('-NoLogo','-NoProfile','-NonInteractive','-ExecutionPolicy',"
        "'Bypass','-File',$launcher,'-LauncherExternalSha256',$expected,"
        + values
        + ");& $powershell @a;$code=$LASTEXITCODE"
        "}finally{$handle.Dispose()};exit $code"
    )
    if len(command) > MAX_RENDERED_COMMAND_CHARS:
        raise R002FExternalDeploymentBundleError(
            "rendered Windows command exceeds safety bound"
        )
    return command


__all__ = [
    "REVIEWED_LAUNCHER_SHA256",
    "REVIEWED_STAGE0_SHA256",
    "PinnedArtifact",
    "PreflightAuthority",
    "R002FExternalDeploymentAuthorityBundle",
    "R002FExternalDeploymentBundleError",
    "SealedTreeAuthority",
    "render_os_trusted_launcher_command",
]
