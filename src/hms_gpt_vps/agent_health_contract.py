from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath
from typing import Mapping, Sequence


AGENT_HEALTH_SCHEMA_VERSION = 1
DEFAULT_REQUIRED_CAPABILITIES = frozenset(
    {
        "workspace.read",
        "workspace.write",
        "process.test",
        "git.status",
        "audit.read",
    }
)
_FORBIDDEN_HEALTH_KEYS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "password",
        "secret",
        "api_key",
        "pairing_token",
        "authorization",
        "cookie",
    }
)


@dataclass(frozen=True)
class AgentHealthExpectation:
    instance_id: str
    workspace_root: str = r"C:\HMS-Workspace"
    required_capabilities: frozenset[str] = DEFAULT_REQUIRED_CAPABILITIES

    def validate(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not self.workspace_root.strip():
            raise ValueError("workspace_root is required")
        if not self.required_capabilities:
            raise ValueError("at least one required capability is required")
        for capability in self.required_capabilities:
            _validate_capability(capability)


@dataclass(frozen=True)
class AgentHealthDocument:
    schema_version: int
    status: str
    instance_id: str
    agent_version: str
    workspace_root: str
    capabilities: tuple[str, ...]
    service_identity: str
    listener_scope: str
    privilege: str
    boot_id: str

    def capability_set(self) -> frozenset[str]:
        return frozenset(self.capabilities)


def _validate_capability(capability: str) -> None:
    if not capability or capability.strip() != capability:
        raise ValueError("capability names must be non-empty and trimmed")
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789._-"
    if any(char not in allowed for char in capability):
        raise ValueError(f"unsupported capability name: {capability}")


def _windows_path_key(path: str) -> str:
    return str(PureWindowsPath(path)).casefold()


def _reject_secret_fields(value: object, *, path: str = "health") -> None:
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key).casefold()
            if key in _FORBIDDEN_HEALTH_KEYS:
                raise ValueError(f"secret-bearing field is forbidden in health document: {path}.{raw_key}")
            _reject_secret_fields(child, path=f"{path}.{raw_key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_secret_fields(child, path=f"{path}[{index}]")


def parse_agent_health(
    payload: Mapping[str, object],
    expectation: AgentHealthExpectation,
) -> AgentHealthDocument:
    """Validate one local Agent `/healthz` document and fail closed on drift."""
    expectation.validate()
    _reject_secret_fields(payload)

    required_fields = {
        "schema_version",
        "status",
        "instance_id",
        "agent_version",
        "workspace_root",
        "capabilities",
        "service_identity",
        "listener_scope",
        "privilege",
        "boot_id",
    }
    missing = sorted(required_fields.difference(payload.keys()))
    if missing:
        raise ValueError(f"agent health document is missing fields: {', '.join(missing)}")

    schema_version = payload["schema_version"]
    if not isinstance(schema_version, int) or isinstance(schema_version, bool):
        raise ValueError("agent health schema_version must be an integer")
    if schema_version != AGENT_HEALTH_SCHEMA_VERSION:
        raise ValueError(f"unsupported agent health schema: {schema_version}")

    status = payload["status"]
    instance_id = payload["instance_id"]
    agent_version = payload["agent_version"]
    workspace_root = payload["workspace_root"]
    service_identity = payload["service_identity"]
    listener_scope = payload["listener_scope"]
    privilege = payload["privilege"]
    boot_id = payload["boot_id"]
    capabilities_raw = payload["capabilities"]

    scalar_values = {
        "status": status,
        "instance_id": instance_id,
        "agent_version": agent_version,
        "workspace_root": workspace_root,
        "service_identity": service_identity,
        "listener_scope": listener_scope,
        "privilege": privilege,
        "boot_id": boot_id,
    }
    for name, value in scalar_values.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"agent health {name} must be a non-empty string")

    if status != "ok":
        raise ValueError(f"agent application health is not ok: {status}")
    if instance_id != expectation.instance_id:
        raise ValueError("agent health instance_id does not match managed instance")
    if _windows_path_key(workspace_root) != _windows_path_key(expectation.workspace_root):
        raise ValueError("agent health workspace_root does not match managed workspace")
    if service_identity.casefold() != r"NT SERVICE\HMSAgent".casefold():
        raise ValueError("agent health service identity is not HMSAgent service SID")
    if listener_scope != "loopback-only":
        raise ValueError("agent health listener must be loopback-only")
    if privilege != "non-admin":
        raise ValueError("agent application must report non-admin privilege")

    if not isinstance(capabilities_raw, list):
        raise ValueError("agent health capabilities must be a list")
    capabilities: list[str] = []
    for raw in capabilities_raw:
        if not isinstance(raw, str):
            raise ValueError("agent health capability entries must be strings")
        _validate_capability(raw)
        capabilities.append(raw)
    if len(set(capabilities)) != len(capabilities):
        raise ValueError("agent health capabilities contain duplicates")

    capability_set = frozenset(capabilities)
    missing_capabilities = sorted(expectation.required_capabilities.difference(capability_set))
    if missing_capabilities:
        raise ValueError(
            "agent health is missing required capabilities: " + ", ".join(missing_capabilities)
        )

    return AgentHealthDocument(
        schema_version=schema_version,
        status=status,
        instance_id=instance_id,
        agent_version=agent_version,
        workspace_root=workspace_root,
        capabilities=tuple(capabilities),
        service_identity=service_identity,
        listener_scope=listener_scope,
        privilege=privilege,
        boot_id=boot_id,
    )
