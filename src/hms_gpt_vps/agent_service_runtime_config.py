from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping

from .agent_guest_runtime import AgentGuestRuntimeConfig
from .agent_health_server import AgentHealthServerConfig
from .agent_https_client import AgentHttpsClientConfig


AGENT_SERVICE_RUNTIME_SCHEMA_VERSION = 1
DEFAULT_AGENT_RUNTIME_CONFIG_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Agent\agent-runtime.json"
)
MAX_AGENT_RUNTIME_CONFIG_BYTES = 32 * 1024

_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "instance_id",
        "project_id",
        "bridge_origin",
        "workspace_root",
        "state_root",
        "python_executable",
        "git_executable",
        "health_port",
    }
)


class AgentServiceRuntimeConfigError(ValueError):
    pass


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentServiceRuntimeConfigError(f"{name} must be a non-empty string")
    return value


def _require_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise AgentServiceRuntimeConfigError(f"{name} must be an integer")
    return value


def _is_absolute_path_text(value: str) -> bool:
    # Runtime config can be generated/tested on a non-Windows host while still
    # describing the Windows guest. Accept the native host form or an absolute
    # drive/UNC Windows path lexically. The actual guest runtime re-validates
    # using native Windows Path semantics before use.
    return Path(value).is_absolute() or PureWindowsPath(value).is_absolute()


@dataclass(frozen=True)
class AgentServiceRuntimeConfig:
    schema_version: int
    instance_id: str
    project_id: str
    bridge_origin: str
    workspace_root: str
    state_root: str
    python_executable: str
    git_executable: str
    health_port: int = 8765

    def validate(self) -> None:
        if self.schema_version != AGENT_SERVICE_RUNTIME_SCHEMA_VERSION:
            raise AgentServiceRuntimeConfigError(
                "unsupported Agent service runtime config schema_version"
            )
        _require_text(self.instance_id, "instance_id")
        _require_text(self.project_id, "project_id")
        _require_text(self.bridge_origin, "bridge_origin")
        _require_text(self.workspace_root, "workspace_root")
        _require_text(self.state_root, "state_root")
        _require_text(self.python_executable, "python_executable")
        _require_text(self.git_executable, "git_executable")
        _require_int(self.health_port, "health_port")

        AgentHttpsClientConfig(self.bridge_origin).validate()
        AgentHealthServerConfig(port=self.health_port).validate()
        for name, value in (
            ("workspace_root", self.workspace_root),
            ("state_root", self.state_root),
            ("python_executable", self.python_executable),
            ("git_executable", self.git_executable),
        ):
            if not _is_absolute_path_text(value):
                raise AgentServiceRuntimeConfigError(f"{name} must be an absolute path")

    def to_guest_runtime_config(
        self,
        *,
        validate: bool = True,
    ) -> AgentGuestRuntimeConfig:
        if validate:
            self.validate()
        return AgentGuestRuntimeConfig(
            instance_id=self.instance_id,
            project_id=self.project_id,
            bridge_origin=self.bridge_origin,
            python_executable=self.python_executable,
            git_executable=self.git_executable,
            workspace_root=Path(self.workspace_root),
            state_root=Path(self.state_root),
            health_port=self.health_port,
        )

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "instance_id": self.instance_id,
            "project_id": self.project_id,
            "bridge_origin": self.bridge_origin,
            "workspace_root": self.workspace_root,
            "state_root": self.state_root,
            "python_executable": self.python_executable,
            "git_executable": self.git_executable,
            "health_port": self.health_port,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "AgentServiceRuntimeConfig":
        keys = frozenset(raw.keys())
        if keys != _REQUIRED_KEYS:
            missing = sorted(_REQUIRED_KEYS - keys)
            unknown = sorted(keys - _REQUIRED_KEYS)
            detail: list[str] = []
            if missing:
                detail.append("missing=" + ",".join(missing))
            if unknown:
                detail.append("unknown=" + ",".join(unknown))
            raise AgentServiceRuntimeConfigError(
                "Agent service runtime config fields are invalid: " + "; ".join(detail)
            )

        config = cls(
            schema_version=_require_int(raw["schema_version"], "schema_version"),
            instance_id=_require_text(raw["instance_id"], "instance_id"),
            project_id=_require_text(raw["project_id"], "project_id"),
            bridge_origin=_require_text(raw["bridge_origin"], "bridge_origin"),
            workspace_root=_require_text(raw["workspace_root"], "workspace_root"),
            state_root=_require_text(raw["state_root"], "state_root"),
            python_executable=_require_text(raw["python_executable"], "python_executable"),
            git_executable=_require_text(raw["git_executable"], "git_executable"),
            health_port=_require_int(raw["health_port"], "health_port"),
        )
        config.validate()
        return config


def parse_agent_service_runtime_config(data: bytes) -> AgentServiceRuntimeConfig:
    if not data:
        raise AgentServiceRuntimeConfigError("Agent service runtime config is empty")
    if len(data) > MAX_AGENT_RUNTIME_CONFIG_BYTES:
        raise AgentServiceRuntimeConfigError("Agent service runtime config is too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AgentServiceRuntimeConfigError(
            "Agent service runtime config must be UTF-8"
        ) from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AgentServiceRuntimeConfigError(
            "Agent service runtime config contains invalid JSON"
        ) from exc
    if not isinstance(raw, dict):
        raise AgentServiceRuntimeConfigError(
            "Agent service runtime config must be a JSON object"
        )
    return AgentServiceRuntimeConfig.from_mapping(raw)


def load_agent_service_runtime_config(
    path: Path = DEFAULT_AGENT_RUNTIME_CONFIG_PATH,
) -> AgentServiceRuntimeConfig:
    if not path.is_absolute():
        raise AgentServiceRuntimeConfigError(
            "Agent service runtime config path must be absolute"
        )
    if path.is_symlink():
        raise PermissionError("Agent service runtime config must not be a symbolic link")
    if not path.is_file():
        raise FileNotFoundError(path)
    size = path.stat().st_size
    if size <= 0 or size > MAX_AGENT_RUNTIME_CONFIG_BYTES:
        raise AgentServiceRuntimeConfigError(
            "Agent service runtime config size is outside supported bounds"
        )
    return parse_agent_service_runtime_config(path.read_bytes())
