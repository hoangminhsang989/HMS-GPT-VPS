from __future__ import annotations

from pathlib import Path
import sys
import threading
import time
import types

import pytest

import hms_gpt_vps.bridge_production_service_runtime as runtime_module
from hms_gpt_vps.agent_bridge_firewall import AgentBridgeFirewallConfig
from hms_gpt_vps.agent_bridge_production_tls import AgentBridgeProductionTlsConfig
from hms_gpt_vps.agent_bridge_tls_deployment import (
    AgentBridgeTlsMaterialConfig,
    ManagedGuestBridgeTlsConfig,
)
from hms_gpt_vps.agent_bridge_tls_storage import AgentBridgePrivateKeyStorageConfig
from hms_gpt_vps.bridge_production_assembly import (
    BridgeProductionAssembly,
    BridgeProductionConfig,
)
from hms_gpt_vps.bridge_service_dependency_loader import BridgeServiceSecretDependencies
from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig
from hms_gpt_vps.bridge_production_service_runtime import (
    BridgeProductionServiceRuntime,
    BridgeProductionServiceRuntimeConfig,
    BridgeProductionServiceRuntimeError,
    _default_mcp_asgi_server_factory,
    build_bridge_production_service_runtime,
)
from hms_gpt_vps.hyperv_network import HyperVNetworkConfig
from hms_gpt_vps.mcp_bridge_server import HmsMcpBridgeConfig
from hms_gpt_vps.pairing_exchange import PairingExchangeKey


_SERVICE_SID = "S-1-5-80-123-456-789-1011-1213"
_VM_ID = "12345678-1234-1234-1234-123456789abc"


class _Verifier:
    async def verify_token(self, token: str):
        return None


def _config(tmp_path: Path) -> BridgeProductionServiceRuntimeConfig:
    runtime_root = tmp_path / "runtime"
    (runtime_root / "secrets").mkdir(parents=True)
    network = HyperVNetworkConfig()
    tls_root = tmp_path / "tls-private-key"
    key_path = tls_root / "agent-bridge-private-key.pem"
    tls = AgentBridgeProductionTlsConfig(
        firewall=AgentBridgeFirewallConfig(network=network),
        storage=AgentBridgePrivateKeyStorageConfig(
            storage_root=tls_root,
            private_key_path=key_path,
            private_key_file_sha256="a" * 64,
            bridge_reader_sid=_SERVICE_SID,
        ),
        material=AgentBridgeTlsMaterialConfig(
            network=network,
            certificate_path=tmp_path / "agent-bridge.pem",
            private_key_path=key_path,
            certificate_der_sha256="b" * 64,
            private_key_file_sha256="a" * 64,
        ),
        guest=ManagedGuestBridgeTlsConfig(
            network=network,
            vm_id=_VM_ID,
            vm_name="HMS-VPS-1",
            bridge_origin="https://172.29.240.1:9443",
            server_certificate_der_sha256="b" * 64,
            trust_root_der_sha256="c" * 64,
        ),
    )
    production = BridgeProductionConfig(
        runtime_root=runtime_root,
        provision_state_path=runtime_root / "provision-state.json",
        instance_id="HMS-VPS-1",
        bridge_base_url="https://bridge.example.test",
        mcp=HmsMcpBridgeConfig(
            issuer_url="https://issuer.example.test",
            resource_server_url="https://resource.example.test",
            port=8765,
        ),
    )
    return BridgeProductionServiceRuntimeConfig(
        expected_service_sid=_SERVICE_SID,
        secret_storage=BridgeServiceSecretStorageConfig(
            root=runtime_root / "secrets" / "service-runtime",
            bridge_reader_sid=_SERVICE_SID,
        ),
        production=production,
        tls=tls,
        startup_timeout_seconds=2,
        shutdown_timeout_seconds=2,
    )


def _assembly(config: BridgeProductionConfig) -> BridgeProductionAssembly:
    assembly = object.__new__(BridgeProductionAssembly)
    object.__setattr__(assembly, "config", config)
    object.__setattr__(assembly, "agent_http", object())
    object.__setattr__(assembly, "mcp_server", object())
    return assembly


def test_config_rejects_secret_sid_mismatch(tmp_path: Path) -> None:
    config = _config(tmp_path)
    bad = BridgeProductionServiceRuntimeConfig(
        expected_service_sid=_SERVICE_SID,
        secret_storage=BridgeServiceSecretStorageConfig(
            root=config.secret_storage.root,
            bridge_reader_sid="S-1-5-80-999-888-777-666-555",
        ),
        production=config.production,
        tls=config.tls,
    )
    with pytest.raises(
        BridgeProductionServiceRuntimeError,
        match="secret reader SID differs",
    ):
        bad.validate()


def test_config_requires_service_secret_root_under_runtime_secrets(tmp_path: Path) -> None:
    config = _config(tmp_path)
    other_parent = tmp_path / "other"
    other_parent.mkdir()
    bad = BridgeProductionServiceRuntimeConfig(
        expected_service_sid=_SERVICE_SID,
        secret_storage=BridgeServiceSecretStorageConfig(
            root=other_parent / "service-runtime",
            bridge_reader_sid=_SERVICE_SID,
        ),
        production=config.production,
        tls=config.tls,
    )
    with pytest.raises(
        BridgeProductionServiceRuntimeError,
        match="outside the production Bridge secrets directory",
    ):
        bad.validate()


def test_factory_proves_identity_before_secret_load_and_after_assembly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    assembly = _assembly(config.production)
    calls: list[str] = []
    secret_dependencies = BridgeServiceSecretDependencies(
        pairing_exchange_key=PairingExchangeKey(b"k" * 32),
        request_credential_resolver=lambda instance_id, device_id: None,
        command_credential_resolver=lambda instance_id: None,
    )

    monkeypatch.setattr(
        runtime_module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: calls.append("identity") or {"process_sid": sid},
    )
    monkeypatch.setattr(
        runtime_module,
        "load_bridge_service_secret_dependencies",
        lambda cfg: calls.append("secrets") or secret_dependencies,
    )
    monkeypatch.setattr(
        runtime_module,
        "assemble_production_bridge",
        lambda cfg, deps: calls.append("assemble") or assembly,
    )

    runtime = build_bridge_production_service_runtime(
        config,
        _Verifier(),
        mcp_server_factory=lambda mcp, host, port: object(),
    )
    assert isinstance(runtime, BridgeProductionServiceRuntime)
    assert calls == ["identity", "secrets", "assemble", "identity"]


class _FakeTlsRuntime:
    def __init__(self) -> None:
        self.bound_address = ("172.29.240.1", 9443)
        self.shutdown_count = 0

    def shutdown(self) -> None:
        self.shutdown_count += 1


class _FakeMcpServer:
    def __init__(self, *, exit_early: bool = False) -> None:
        self.started = False
        self.should_exit = False
        self.force_exit = False
        self.exit_early = exit_early
        self.run_count = 0

    def run(self) -> None:
        self.run_count += 1
        self.started = True
        if self.exit_early:
            return
        while not self.should_exit and not self.force_exit:
            time.sleep(0.005)


def test_runtime_starts_tls_then_mcp_and_shutdowns_both(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    assembly = _assembly(config.production)
    tls_runtime = _FakeTlsRuntime()
    mcp_server = _FakeMcpServer()
    calls: list[str] = []

    monkeypatch.setattr(
        runtime_module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: calls.append("identity") or {"process_sid": sid},
    )
    monkeypatch.setattr(
        runtime_module,
        "start_agent_bridge_production_tls",
        lambda boundary, cfg: calls.append("tls") or tls_runtime,
    )

    runtime = BridgeProductionServiceRuntime(
        config=config,
        assembly=assembly,
        mcp_server_factory=lambda mcp, host, port: (
            calls.append(f"mcp:{host}:{port}") or mcp_server
        ),
    )
    stop = threading.Event()
    stopper = threading.Thread(target=lambda: (time.sleep(0.05), stop.set()))
    stopper.start()
    runtime.run(stop)
    stopper.join(timeout=1)

    assert calls == ["identity", "tls", "mcp:127.0.0.1:8765"]
    assert mcp_server.run_count == 1
    assert mcp_server.should_exit is True
    assert tls_runtime.shutdown_count == 1


def test_runtime_rejects_mcp_early_exit_and_closes_tls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    assembly = _assembly(config.production)
    tls_runtime = _FakeTlsRuntime()
    mcp_server = _FakeMcpServer(exit_early=True)

    monkeypatch.setattr(
        runtime_module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: {"process_sid": sid},
    )
    monkeypatch.setattr(
        runtime_module,
        "start_agent_bridge_production_tls",
        lambda boundary, cfg: tls_runtime,
    )
    runtime = BridgeProductionServiceRuntime(
        config=config,
        assembly=assembly,
        mcp_server_factory=lambda mcp, host, port: mcp_server,
    )

    with pytest.raises(
        BridgeProductionServiceRuntimeError,
        match="exited before",
    ):
        runtime.run(threading.Event())
    assert tls_runtime.shutdown_count == 1


def test_runtime_with_preexisting_stop_opens_no_listener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = _config(tmp_path)
    assembly = _assembly(config.production)
    monkeypatch.setattr(
        runtime_module,
        "start_agent_bridge_production_tls",
        lambda *args: pytest.fail("pre-stopped runtime must not start TLS"),
    )
    runtime = BridgeProductionServiceRuntime(
        config=config,
        assembly=assembly,
        mcp_server_factory=lambda *args: pytest.fail(
            "pre-stopped runtime must not build MCP server"
        ),
    )
    stop = threading.Event()
    stop.set()
    runtime.run(stop)


def test_default_mcp_factory_pins_loopback_and_streamable_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    class FakeMcp:
        def streamable_http_app(self, **kwargs):
            observed["app_kwargs"] = dict(kwargs)
            return "app"

    class FakeConfig:
        def __init__(self, **kwargs):
            observed["uvicorn_config"] = dict(kwargs)

    class FakeServer:
        def __init__(self, config):
            self.config = config
            self.started = False
            self.should_exit = False
            self.force_exit = False

        def run(self) -> None:
            return

    fake_uvicorn = types.SimpleNamespace(Config=FakeConfig, Server=FakeServer)
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)

    server = _default_mcp_asgi_server_factory(FakeMcp(), "127.0.0.1", 8765)
    assert isinstance(server, FakeServer)
    assert observed["app_kwargs"] == {
        "host": "127.0.0.1",
        "streamable_http_path": "/mcp",
        "stateless_http": True,
        "json_response": True,
    }
    assert observed["uvicorn_config"] == {
        "app": "app",
        "host": "127.0.0.1",
        "port": 8765,
        "log_level": "warning",
        "access_log": False,
        "lifespan": "on",
    }


def test_default_mcp_factory_rejects_non_loopback() -> None:
    with pytest.raises(
        BridgeProductionServiceRuntimeError,
        match="exact loopback",
    ):
        _default_mcp_asgi_server_factory(object(), "0.0.0.0", 8765)
