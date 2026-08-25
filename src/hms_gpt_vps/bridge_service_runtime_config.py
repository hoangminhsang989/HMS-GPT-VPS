from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping

from .agent_bridge_firewall import AgentBridgeFirewallConfig
from .agent_bridge_production_tls import AgentBridgeProductionTlsConfig
from .agent_bridge_tls_deployment import (
    AgentBridgeTlsMaterialConfig,
    ManagedGuestBridgeTlsConfig,
)
from .agent_bridge_tls_storage import AgentBridgePrivateKeyStorageConfig
from .bridge_production_assembly import BridgeProductionConfig
from .bridge_production_service_runtime import BridgeProductionServiceRuntimeConfig
from .bridge_service_identity import require_hms_bridge_service_sid
from .bridge_service_secret_storage import BridgeServiceSecretStorageConfig
from .hyperv_network import HyperVNetworkConfig
from .mcp_bridge_server import HmsMcpBridgeConfig
from .pairing_readiness_runtime import PairingReadinessConfig
from .qualification_file_authority import read_file_pinned


BRIDGE_SERVICE_RUNTIME_SCHEMA_VERSION = 1
DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH = Path(
    r"C:\ProgramData\HMS-GPT-VPS\Bridge\bridge-runtime.json"
)
MAX_BRIDGE_RUNTIME_CONFIG_BYTES = 64 * 1024

_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "instance_id",
        "runtime_root",
        "provision_state_path",
        "bridge_base_url",
        "mcp_issuer_url",
        "mcp_resource_server_url",
        "mcp_port",
        "presence_max_age_seconds",
        "pair_ttl_seconds",
        "tls_certificate_path",
        "tls_private_key_path",
        "tls_storage_root",
        "tls_certificate_der_sha256",
        "tls_private_key_file_sha256",
        "tls_port",
        "vm_id",
        "vm_name",
        "trust_root_der_sha256",
    }
)


class BridgeServiceRuntimeConfigError(ValueError):
    pass


def _require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BridgeServiceRuntimeConfigError(
            f"{name} must be non-empty canonical text"
        )
    return value


def _require_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise BridgeServiceRuntimeConfigError(f"{name} must be an integer")
    return value


def _require_sha256(value: object, name: str) -> str:
    text = _require_text(value, name)
    if (
        len(text) != 64
        or text != text.lower()
        or any(char not in "0123456789abcdef" for char in text)
    ):
        raise BridgeServiceRuntimeConfigError(
            f"{name} must be canonical lowercase SHA-256 hex"
        )
    return text


def _require_absolute_path_text(value: object, name: str) -> str:
    text = _require_text(value, name)
    if not (Path(text).is_absolute() or PureWindowsPath(text).is_absolute()):
        raise BridgeServiceRuntimeConfigError(f"{name} must be an absolute path")
    if any(part in {".", ".."} for part in PureWindowsPath(text).parts):
        raise BridgeServiceRuntimeConfigError(
            f"{name} must not contain dot traversal segments"
        )
    return text


def _no_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BridgeServiceRuntimeConfigError(
                f"duplicate Bridge runtime config key: {key}"
            )
        result[key] = value
    return result


@dataclass(frozen=True)
class BridgeServiceRuntimeConfig:
    schema_version: int
    instance_id: str
    runtime_root: str
    provision_state_path: str
    bridge_base_url: str
    mcp_issuer_url: str
    mcp_resource_server_url: str
    mcp_port: int
    presence_max_age_seconds: int
    pair_ttl_seconds: int
    tls_certificate_path: str
    tls_private_key_path: str
    tls_storage_root: str
    tls_certificate_der_sha256: str
    tls_private_key_file_sha256: str
    tls_port: int
    vm_id: str
    vm_name: str
    trust_root_der_sha256: str

    def validate(self) -> None:
        if self.schema_version != BRIDGE_SERVICE_RUNTIME_SCHEMA_VERSION:
            raise BridgeServiceRuntimeConfigError(
                "unsupported Bridge service runtime config schema_version"
            )
        _require_text(self.instance_id, "instance_id")
        _require_absolute_path_text(self.runtime_root, "runtime_root")
        _require_absolute_path_text(
            self.provision_state_path,
            "provision_state_path",
        )
        _require_text(self.bridge_base_url, "bridge_base_url")
        _require_text(self.mcp_issuer_url, "mcp_issuer_url")
        _require_text(
            self.mcp_resource_server_url,
            "mcp_resource_server_url",
        )
        _require_int(self.mcp_port, "mcp_port")
        _require_int(
            self.presence_max_age_seconds,
            "presence_max_age_seconds",
        )
        _require_int(self.pair_ttl_seconds, "pair_ttl_seconds")
        _require_absolute_path_text(
            self.tls_certificate_path,
            "tls_certificate_path",
        )
        _require_absolute_path_text(
            self.tls_private_key_path,
            "tls_private_key_path",
        )
        _require_absolute_path_text(
            self.tls_storage_root,
            "tls_storage_root",
        )
        _require_sha256(
            self.tls_certificate_der_sha256,
            "tls_certificate_der_sha256",
        )
        _require_sha256(
            self.tls_private_key_file_sha256,
            "tls_private_key_file_sha256",
        )
        _require_int(self.tls_port, "tls_port")
        _require_text(self.vm_id, "vm_id")
        _require_text(self.vm_name, "vm_name")
        _require_sha256(
            self.trust_root_der_sha256,
            "trust_root_der_sha256",
        )

        network = HyperVNetworkConfig()
        network.validate()
        HmsMcpBridgeConfig(
            issuer_url=self.mcp_issuer_url,
            resource_server_url=self.mcp_resource_server_url,
            port=self.mcp_port,
        ).validate()
        PairingReadinessConfig(
            instance_id=self.instance_id,
            bridge_base_url=self.bridge_base_url,
            presence_max_age_seconds=self.presence_max_age_seconds,
            pair_ttl_seconds=self.pair_ttl_seconds,
        ).validate()
        AgentBridgeFirewallConfig(
            network=network,
            port=self.tls_port,
        ).validate()

    def to_runtime_config(
        self,
        expected_service_sid: str,
        *,
        validate: bool = True,
    ) -> BridgeProductionServiceRuntimeConfig:
        if validate:
            self.validate()
        service_sid = require_hms_bridge_service_sid(expected_service_sid)
        network = HyperVNetworkConfig()
        bridge_origin = f"https://{network.gateway}:{self.tls_port}"

        production = BridgeProductionConfig(
            runtime_root=Path(self.runtime_root),
            provision_state_path=Path(self.provision_state_path),
            instance_id=self.instance_id,
            bridge_base_url=self.bridge_base_url,
            mcp=HmsMcpBridgeConfig(
                issuer_url=self.mcp_issuer_url,
                resource_server_url=self.mcp_resource_server_url,
                port=self.mcp_port,
            ),
            presence_max_age_seconds=self.presence_max_age_seconds,
            pair_ttl_seconds=self.pair_ttl_seconds,
        )
        tls_storage = AgentBridgePrivateKeyStorageConfig(
            storage_root=Path(self.tls_storage_root),
            private_key_path=Path(self.tls_private_key_path),
            private_key_file_sha256=self.tls_private_key_file_sha256,
            bridge_reader_sid=service_sid,
        )
        tls_material = AgentBridgeTlsMaterialConfig(
            network=network,
            certificate_path=Path(self.tls_certificate_path),
            private_key_path=Path(self.tls_private_key_path),
            certificate_der_sha256=self.tls_certificate_der_sha256,
            private_key_file_sha256=self.tls_private_key_file_sha256,
            port=self.tls_port,
        )
        guest = ManagedGuestBridgeTlsConfig(
            network=network,
            vm_id=self.vm_id,
            vm_name=self.vm_name,
            bridge_origin=bridge_origin,
            server_certificate_der_sha256=self.tls_certificate_der_sha256,
            trust_root_der_sha256=self.trust_root_der_sha256,
            port=self.tls_port,
        )
        tls = AgentBridgeProductionTlsConfig(
            firewall=AgentBridgeFirewallConfig(
                network=network,
                port=self.tls_port,
            ),
            storage=tls_storage,
            material=tls_material,
            guest=guest,
        )
        secret_storage = BridgeServiceSecretStorageConfig(
            root=Path(self.runtime_root) / "secrets" / "service-runtime",
            bridge_reader_sid=service_sid,
        )
        runtime = BridgeProductionServiceRuntimeConfig(
            expected_service_sid=service_sid,
            secret_storage=secret_storage,
            production=production,
            tls=tls,
        )
        runtime.validate()
        return runtime

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "instance_id": self.instance_id,
            "runtime_root": self.runtime_root,
            "provision_state_path": self.provision_state_path,
            "bridge_base_url": self.bridge_base_url,
            "mcp_issuer_url": self.mcp_issuer_url,
            "mcp_resource_server_url": self.mcp_resource_server_url,
            "mcp_port": self.mcp_port,
            "presence_max_age_seconds": self.presence_max_age_seconds,
            "pair_ttl_seconds": self.pair_ttl_seconds,
            "tls_certificate_path": self.tls_certificate_path,
            "tls_private_key_path": self.tls_private_key_path,
            "tls_storage_root": self.tls_storage_root,
            "tls_certificate_der_sha256": self.tls_certificate_der_sha256,
            "tls_private_key_file_sha256": self.tls_private_key_file_sha256,
            "tls_port": self.tls_port,
            "vm_id": self.vm_id,
            "vm_name": self.vm_name,
            "trust_root_der_sha256": self.trust_root_der_sha256,
        }

    @classmethod
    def from_mapping(
        cls,
        raw: Mapping[str, Any],
    ) -> "BridgeServiceRuntimeConfig":
        keys = frozenset(raw.keys())
        if keys != _REQUIRED_KEYS:
            missing = sorted(_REQUIRED_KEYS - keys)
            unknown = sorted(keys - _REQUIRED_KEYS)
            detail: list[str] = []
            if missing:
                detail.append("missing=" + ",".join(missing))
            if unknown:
                detail.append("unknown=" + ",".join(unknown))
            raise BridgeServiceRuntimeConfigError(
                "Bridge service runtime config fields are invalid: "
                + "; ".join(detail)
            )

        config = cls(
            schema_version=_require_int(
                raw["schema_version"],
                "schema_version",
            ),
            instance_id=_require_text(raw["instance_id"], "instance_id"),
            runtime_root=_require_absolute_path_text(
                raw["runtime_root"],
                "runtime_root",
            ),
            provision_state_path=_require_absolute_path_text(
                raw["provision_state_path"],
                "provision_state_path",
            ),
            bridge_base_url=_require_text(
                raw["bridge_base_url"],
                "bridge_base_url",
            ),
            mcp_issuer_url=_require_text(
                raw["mcp_issuer_url"],
                "mcp_issuer_url",
            ),
            mcp_resource_server_url=_require_text(
                raw["mcp_resource_server_url"],
                "mcp_resource_server_url",
            ),
            mcp_port=_require_int(raw["mcp_port"], "mcp_port"),
            presence_max_age_seconds=_require_int(
                raw["presence_max_age_seconds"],
                "presence_max_age_seconds",
            ),
            pair_ttl_seconds=_require_int(
                raw["pair_ttl_seconds"],
                "pair_ttl_seconds",
            ),
            tls_certificate_path=_require_absolute_path_text(
                raw["tls_certificate_path"],
                "tls_certificate_path",
            ),
            tls_private_key_path=_require_absolute_path_text(
                raw["tls_private_key_path"],
                "tls_private_key_path",
            ),
            tls_storage_root=_require_absolute_path_text(
                raw["tls_storage_root"],
                "tls_storage_root",
            ),
            tls_certificate_der_sha256=_require_sha256(
                raw["tls_certificate_der_sha256"],
                "tls_certificate_der_sha256",
            ),
            tls_private_key_file_sha256=_require_sha256(
                raw["tls_private_key_file_sha256"],
                "tls_private_key_file_sha256",
            ),
            tls_port=_require_int(raw["tls_port"], "tls_port"),
            vm_id=_require_text(raw["vm_id"], "vm_id"),
            vm_name=_require_text(raw["vm_name"], "vm_name"),
            trust_root_der_sha256=_require_sha256(
                raw["trust_root_der_sha256"],
                "trust_root_der_sha256",
            ),
        )
        config.validate()
        return config


def parse_bridge_service_runtime_config(
    data: bytes,
) -> BridgeServiceRuntimeConfig:
    if not isinstance(data, bytes):
        raise TypeError("Bridge service runtime config must be bytes")
    if not data:
        raise BridgeServiceRuntimeConfigError(
            "Bridge service runtime config is empty"
        )
    if len(data) > MAX_BRIDGE_RUNTIME_CONFIG_BYTES:
        raise BridgeServiceRuntimeConfigError(
            "Bridge service runtime config is too large"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeServiceRuntimeConfigError(
            "Bridge service runtime config must be UTF-8"
        ) from exc
    try:
        raw = json.loads(
            text,
            object_pairs_hook=_no_duplicate_json_keys,
        )
    except json.JSONDecodeError as exc:
        raise BridgeServiceRuntimeConfigError(
            "Bridge service runtime config contains invalid JSON"
        ) from exc
    if not isinstance(raw, dict):
        raise BridgeServiceRuntimeConfigError(
            "Bridge service runtime config must be a JSON object"
        )
    return BridgeServiceRuntimeConfig.from_mapping(raw)


def load_bridge_service_runtime_config(
    path: Path = DEFAULT_BRIDGE_RUNTIME_CONFIG_PATH,
) -> BridgeServiceRuntimeConfig:
    if not isinstance(path, Path):
        raise TypeError("Bridge service runtime config path must be pathlib.Path")
    data = read_file_pinned(
        path,
        max_bytes=MAX_BRIDGE_RUNTIME_CONFIG_BYTES,
        label="Bridge service runtime config",
    )
    return parse_bridge_service_runtime_config(data)
