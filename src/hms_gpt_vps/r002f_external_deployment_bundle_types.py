from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import PureWindowsPath
from typing import Mapping

REVIEWED_LAUNCHER_SHA256 = (
    "0f2c12973ede984b3eb55ec26284bb068b1d4f9050b1a5f629fff0ac71f863f6"
)
REVIEWED_STAGE0_SHA256 = (
    "3b14890a51b7d51aaac0105d1f3149a85c2c0e9b10208f25b4cc8f61130c787f"
)
LAUNCHER_FILENAME = "run_r002f_external_sealed_preparation_launcher.ps1"
STAGE0_FILENAME = "run_r002f_external_sealed_preparation_stage0.ps1"
MAX_AUTHORITY_TEXT_CHARS = 4096

PATH_FIELDS = frozenset(
    {
        "run_dir",
        "package_root",
        "package_manifest",
        "runtime_config",
        "instance_registry",
        "instance_runtime_dir",
        "bridge_device_credential",
        "trust_root_certificate",
    }
)
TEXT_FIELDS = frozenset(
    {
        "challenge_source_commit",
        "challenge_workspace_path",
        "challenge_expected_sha256",
    }
)
_RESERVED_WINDOWS_NAMES = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }
)


class R002FExternalDeploymentBundleError(RuntimeError):
    pass


def sha1(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise R002FExternalDeploymentBundleError(
            f"{label} must be canonical lowercase SHA-1"
        )
    return value


def sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise R002FExternalDeploymentBundleError(
            f"{label} must be canonical lowercase SHA-256"
        )
    return value


def windows_absolute(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_AUTHORITY_TEXT_CHARS
        or "/" in value
        or "\x00" in value
    ):
        raise R002FExternalDeploymentBundleError(
            f"{label} must be a canonical absolute Windows path"
        )
    path = PureWindowsPath(value)
    if not path.is_absolute() or str(path) != value:
        raise R002FExternalDeploymentBundleError(
            f"{label} must be a canonical absolute Windows path"
        )
    for part in path.parts[1:]:
        if part in {".", ".."} or part.endswith((" ", ".")):
            raise R002FExternalDeploymentBundleError(
                f"{label} contains an unsafe Windows path component"
            )
        if part.split(".", 1)[0].upper() in _RESERVED_WINDOWS_NAMES:
            raise R002FExternalDeploymentBundleError(
                f"{label} contains a reserved Windows path component"
            )
    return value


def same(left: str, right: str) -> bool:
    return (
        str(PureWindowsPath(left)).casefold()
        == str(PureWindowsPath(right)).casefold()
    )


def direct_child(child: str, parent: str) -> bool:
    return same(str(PureWindowsPath(child).parent), parent)


def within(child: str, parent: str) -> bool:
    child_parts = tuple(part.casefold() for part in PureWindowsPath(child).parts)
    parent_parts = tuple(part.casefold() for part in PureWindowsPath(parent).parts)
    return (
        len(child_parts) > len(parent_parts)
        and child_parts[: len(parent_parts)] == parent_parts
    )


def strict_object(
    raw: object, names: frozenset[str], label: str
) -> Mapping[str, object]:
    if not isinstance(raw, dict) or frozenset(raw) != names:
        raise R002FExternalDeploymentBundleError(f"{label} fields are invalid")
    return raw


@dataclass(frozen=True)
class PinnedArtifact:
    path: str
    sha256: str

    def validate(self, *, label: str, filename: str | None = None) -> None:
        windows_absolute(self.path, f"{label} path")
        sha256(self.sha256, f"{label} SHA-256")
        if filename is not None and PureWindowsPath(self.path).name != filename:
            raise R002FExternalDeploymentBundleError(f"{label} filename differs")

    @classmethod
    def from_mapping(cls, raw: object, *, label: str) -> "PinnedArtifact":
        obj = strict_object(raw, frozenset({"path", "sha256"}), label)
        path, digest = obj.get("path"), obj.get("sha256")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise R002FExternalDeploymentBundleError(
                f"{label} field types are invalid"
            )
        item = cls(path=path, sha256=digest)
        item.validate(label=label)
        return item


@dataclass(frozen=True)
class SealedTreeAuthority:
    source_root: str
    manifest_path: str
    manifest_sha256: str
    destination_root: str

    def validate(self, *, label: str) -> None:
        windows_absolute(self.source_root, f"{label} source_root")
        windows_absolute(self.manifest_path, f"{label} manifest_path")
        sha256(self.manifest_sha256, f"{label} manifest SHA-256")
        windows_absolute(self.destination_root, f"{label} destination_root")

    def to_dict(self) -> dict[str, object]:
        self.validate(label="sealed tree")
        return {
            "source_root": self.source_root,
            "manifest_path": self.manifest_path,
            "manifest_sha256": self.manifest_sha256,
            "destination_root": self.destination_root,
        }

    @classmethod
    def from_mapping(
        cls, raw: object, *, label: str
    ) -> "SealedTreeAuthority":
        obj = strict_object(
            raw,
            frozenset(
                {
                    "source_root",
                    "manifest_path",
                    "manifest_sha256",
                    "destination_root",
                }
            ),
            label,
        )
        values = tuple(
            obj.get(name)
            for name in (
                "source_root",
                "manifest_path",
                "manifest_sha256",
                "destination_root",
            )
        )
        if any(not isinstance(value, str) for value in values):
            raise R002FExternalDeploymentBundleError(
                f"{label} field types are invalid"
            )
        item = cls(*values)
        item.validate(label=label)
        return item


@dataclass(frozen=True)
class PreflightAuthority:
    run_dir: str
    package_root: str
    package_manifest: str
    runtime_config: str
    instance_registry: str
    instance_runtime_dir: str
    bridge_device_credential: str
    trust_root_certificate: str
    challenge_source_commit: str
    challenge_workspace_path: str
    challenge_expected_sha256: str
    max_reconcile_steps: int
    external_timeout_seconds: float
    step_timeout_seconds: float

    def validate(self) -> None:
        for name in sorted(PATH_FIELDS):
            windows_absolute(getattr(self, name), f"preflight {name}")
        sha1(self.challenge_source_commit, "preflight challenge_source_commit")
        windows_absolute(
            self.challenge_workspace_path,
            "preflight challenge_workspace_path",
        )
        sha256(
            self.challenge_expected_sha256,
            "preflight challenge_expected_sha256",
        )
        if (
            not isinstance(self.max_reconcile_steps, int)
            or isinstance(self.max_reconcile_steps, bool)
            or not 1 <= self.max_reconcile_steps <= 32
        ):
            raise R002FExternalDeploymentBundleError(
                "preflight max_reconcile_steps must be between 1 and 32"
            )
        for name in ("external_timeout_seconds", "step_timeout_seconds"):
            value = getattr(self, name)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(float(value))
                or float(value) <= 0
            ):
                raise R002FExternalDeploymentBundleError(
                    f"preflight {name} must be positive and finite"
                )
        if float(self.step_timeout_seconds) <= float(
            self.external_timeout_seconds
        ):
            raise R002FExternalDeploymentBundleError(
                "preflight step_timeout_seconds must exceed "
                "external_timeout_seconds"
            )

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "run_dir": self.run_dir,
            "package_root": self.package_root,
            "package_manifest": self.package_manifest,
            "runtime_config": self.runtime_config,
            "instance_registry": self.instance_registry,
            "instance_runtime_dir": self.instance_runtime_dir,
            "bridge_device_credential": self.bridge_device_credential,
            "trust_root_certificate": self.trust_root_certificate,
            "challenge_source_commit": self.challenge_source_commit,
            "challenge_workspace_path": self.challenge_workspace_path,
            "challenge_expected_sha256": self.challenge_expected_sha256,
            "max_reconcile_steps": self.max_reconcile_steps,
            "external_timeout_seconds": float(self.external_timeout_seconds),
            "step_timeout_seconds": float(self.step_timeout_seconds),
        }

    @classmethod
    def from_mapping(cls, raw: object) -> "PreflightAuthority":
        names = PATH_FIELDS | TEXT_FIELDS | frozenset(
            {
                "max_reconcile_steps",
                "external_timeout_seconds",
                "step_timeout_seconds",
            }
        )
        obj = strict_object(raw, names, "preflight authority")
        kwargs = {name: obj.get(name) for name in names}
        for name in PATH_FIELDS | TEXT_FIELDS:
            if not isinstance(kwargs[name], str):
                raise R002FExternalDeploymentBundleError(
                    f"preflight {name} type is invalid"
                )
        if (
            type(kwargs["max_reconcile_steps"]) is not int
            or type(kwargs["external_timeout_seconds"]) not in {int, float}
            or type(kwargs["step_timeout_seconds"]) not in {int, float}
        ):
            raise R002FExternalDeploymentBundleError(
                "preflight numeric field types are invalid"
            )
        item = cls(**kwargs)
        item.validate()
        return item
