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
from hms_gpt_vps.agent_bridge_tls_deployment import AgentBridgeTlsMaterialConfig, ManagedGuestBridgeTlsConfig
from hms_gpt_vps.agent_bridge_tls_storage import AgentBridgePrivateKeyStorageConfig
from hms_gpt_vps.bridge_production_assembly import BridgeProductionAssembly, BridgeProductionConfig
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
_TUNNEL_ID = "tunnel_" + "a" * 32
_INGRESS_TOKEN = "d" * 64


class _Verifier:
    async def verify_token(self, token: str): return None


def _config(tmp_path: Path) -> BridgeProductionServiceRuntimeConfig:
    runtime_root = tmp_path / "runtime"; (runtime_root / "secrets").mkdir(parents=True)
    network = HyperVNetworkConfig(); tls_root = tmp_path / "tls-private-key"; key_path = tls_root / "agent-bridge-private-key.pem"
    tls = AgentBridgeProductionTlsConfig(
        firewall=AgentBridgeFirewallConfig(network=network),
        storage=AgentBridgePrivateKeyStorageConfig(storage_root=tls_root, private_key_path=key_path, private_key_file_sha256="a"*64, bridge_reader_sid=_SERVICE_SID),
        material=AgentBridgeTlsMaterialConfig(network=network, certificate_path=tmp_path/"agent-bridge.pem", private_key_path=key_path, certificate_der_sha256="b"*64, private_key_file_sha256="a"*64),
        guest=ManagedGuestBridgeTlsConfig(network=network, vm_id=_VM_ID, vm_name="HMS-VPS-1", bridge_origin="https://172.29.240.1:9443", server_certificate_der_sha256="b"*64, trust_root_der_sha256="c"*64),
    )
    production = BridgeProductionConfig(
        runtime_root=runtime_root, provision_state_path=runtime_root/"provision-state.json", instance_id="HMS-VPS-1",
        bridge_base_url="https://bridge.example.test",
        mcp=HmsMcpBridgeConfig(issuer_url="https://issuer.example.test", resource_server_url="https://resource.example.test", port=8765),
    )
    return BridgeProductionServiceRuntimeConfig(
        expected_service_sid=_SERVICE_SID,
        secret_storage=BridgeServiceSecretStorageConfig(root=runtime_root/"secrets"/"service-runtime", bridge_reader_sid=_SERVICE_SID),
        production=production, tls=tls, tunnel_id=_TUNNEL_ID, startup_timeout_seconds=2, shutdown_timeout_seconds=2,
    )


def _assembly(config: BridgeProductionConfig) -> BridgeProductionAssembly:
    assembly = object.__new__(BridgeProductionAssembly)
    object.__setattr__(assembly, "config", config); object.__setattr__(assembly, "agent_http", object()); object.__setattr__(assembly, "mcp_server", object())
    return assembly


def test_config_rejects_secret_sid_mismatch(tmp_path: Path) -> None:
    config=_config(tmp_path)
    bad=BridgeProductionServiceRuntimeConfig(expected_service_sid=_SERVICE_SID, secret_storage=BridgeServiceSecretStorageConfig(root=config.secret_storage.root, bridge_reader_sid="S-1-5-80-999-888-777-666-555"), production=config.production, tls=config.tls, tunnel_id=_TUNNEL_ID)
    with pytest.raises(BridgeProductionServiceRuntimeError, match="secret reader SID differs"): bad.validate()


def test_config_requires_service_secret_root_under_runtime_secrets(tmp_path: Path) -> None:
    config=_config(tmp_path); other=tmp_path/"other"; other.mkdir()
    bad=BridgeProductionServiceRuntimeConfig(expected_service_sid=_SERVICE_SID, secret_storage=BridgeServiceSecretStorageConfig(root=other/"service-runtime", bridge_reader_sid=_SERVICE_SID), production=config.production, tls=config.tls, tunnel_id=_TUNNEL_ID)
    with pytest.raises(BridgeProductionServiceRuntimeError, match="outside the production Bridge secrets directory"): bad.validate()


def test_config_rejects_bad_tunnel_id_and_nonfixed_mcp_port(tmp_path: Path) -> None:
    config=_config(tmp_path)
    bad=BridgeProductionServiceRuntimeConfig(config.expected_service_sid,config.secret_storage,config.production,config.tls,"tunnel_BAD")
    with pytest.raises(BridgeProductionServiceRuntimeError,match="tunnel_id"): bad.validate()
    object.__setattr__(config.production.mcp,"port",8766)
    with pytest.raises(BridgeProductionServiceRuntimeError,match="MCP port"): config.validate()


def test_factory_proves_identity_before_secret_load_and_after_assembly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production); calls=[]
    secret_dependencies=BridgeServiceSecretDependencies(pairing_exchange_key=PairingExchangeKey(b"k"*32),request_credential_resolver=lambda i,d:None,command_credential_resolver=lambda i:None)
    monkeypatch.setattr(runtime_module,"prove_hms_bridge_runtime_identity",lambda sid:calls.append("identity") or {"process_sid":sid})
    monkeypatch.setattr(runtime_module,"load_bridge_service_secret_dependencies",lambda cfg:calls.append("secrets") or secret_dependencies)
    monkeypatch.setattr(runtime_module,"assemble_production_bridge",lambda cfg,deps:calls.append("assemble") or assembly)
    runtime=build_bridge_production_service_runtime(config,_Verifier(),mcp_server_factory=lambda *a:object(),tunnel_runtime_factory=lambda c, token:object())
    assert isinstance(runtime,BridgeProductionServiceRuntime)
    assert calls==["identity","secrets","assemble","identity"]


class _FakeTlsRuntime:
    def __init__(self,calls=None): self.bound_address=("172.29.240.1",9443); self.shutdown_count=0; self.calls=calls
    def shutdown(self):
        self.shutdown_count+=1
        if self.calls is not None: self.calls.append("tls-down")


class _FakeMcpServer:
    def __init__(self,*,exit_early=False,calls=None): self.started=False; self.should_exit=False; self.force_exit=False; self.exit_early=exit_early; self.run_count=0; self.calls=calls
    def run(self):
        self.run_count+=1; self.started=True
        if self.calls is not None: self.calls.append("mcp-run")
        if self.exit_early: return
        while not self.should_exit and not self.force_exit: time.sleep(0.005)


class _FakeTunnel:
    def __init__(self,*,start_value=True,calls=None): self._ready=False; self.start_value=start_value; self.calls=calls; self.health_count=0; self.fail=False; self.shutdown_count=0
    @property
    def ready(self): return self._ready
    def start(self,stop):
        if self.calls is not None: self.calls.append("tunnel-start")
        self._ready=self.start_value; return self.start_value
    def assert_healthy(self):
        self.health_count+=1
        if self.calls is not None: self.calls.append("tunnel-health")
        if self.fail: raise RuntimeError("tunnel lost")
    def shutdown(self):
        self.shutdown_count+=1; self._ready=False
        if self.calls is not None: self.calls.append("tunnel-down")


def test_runtime_starts_tls_then_mcp_then_tunnel_and_shutdowns_in_reverse_ingress_order(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production); calls=[]; tls=_FakeTlsRuntime(calls); mcp=_FakeMcpServer(calls=calls); tunnel=_FakeTunnel(calls=calls)
    monkeypatch.setattr(runtime_module,"prove_hms_bridge_runtime_identity",lambda sid:calls.append("identity") or {"process_sid":sid})
    monkeypatch.setattr(runtime_module,"start_agent_bridge_production_tls",lambda *a:calls.append("tls") or tls)
    runtime=BridgeProductionServiceRuntime(config,assembly,mcp_server_factory=lambda *a:calls.append("mcp-build") or mcp,tunnel_runtime_factory=lambda c, token:calls.append("tunnel-build") or tunnel)
    stop=threading.Event(); assert runtime.start(stop) is True; assert runtime.ready is True
    assert calls[:9]==["identity","tls","mcp-build","mcp-run","tunnel-build","tunnel-start","tunnel-health","identity"][:9]
    runtime.shutdown()
    assert calls.index("tunnel-down") < calls.index("tls-down")
    assert mcp.should_exit is True and tls.shutdown_count==1 and tunnel.shutdown_count==1


def test_runtime_passes_one_generated_ingress_token_to_mcp_and_tunnel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production); tls=_FakeTlsRuntime(); mcp=_FakeMcpServer(); tunnel=_FakeTunnel(); observed={}
    monkeypatch.setattr(runtime_module,"generate_mcp_tunnel_ingress_token",lambda:_INGRESS_TOKEN)
    monkeypatch.setattr(runtime_module,"prove_hms_bridge_runtime_identity",lambda sid:{"process_sid":sid})
    monkeypatch.setattr(runtime_module,"start_agent_bridge_production_tls",lambda *a:tls)
    def mcp_factory(server,host,port,token):
        observed["mcp_token"]=token; return mcp
    def tunnel_factory(runtime_config,token):
        observed["tunnel_token"]=token; return tunnel
    runtime=BridgeProductionServiceRuntime(config,assembly,mcp_server_factory=mcp_factory,tunnel_runtime_factory=tunnel_factory)
    assert runtime.start(threading.Event()) is True
    assert observed=={"mcp_token":_INGRESS_TOKEN,"tunnel_token":_INGRESS_TOKEN}
    runtime.shutdown()


def test_runtime_rejects_mcp_early_exit_and_never_starts_tunnel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production); tls=_FakeTlsRuntime(); mcp=_FakeMcpServer(exit_early=True); tunnel=_FakeTunnel()
    monkeypatch.setattr(runtime_module,"prove_hms_bridge_runtime_identity",lambda sid:{"process_sid":sid})
    monkeypatch.setattr(runtime_module,"start_agent_bridge_production_tls",lambda *a:tls)
    runtime=BridgeProductionServiceRuntime(config,assembly,mcp_server_factory=lambda *a:mcp,tunnel_runtime_factory=lambda c, token:tunnel)
    with pytest.raises(BridgeProductionServiceRuntimeError,match="exited before"): runtime.run(threading.Event())
    assert tls.shutdown_count==1 and tunnel.shutdown_count==0


def test_tunnel_start_failure_rolls_back_tunnel_mcp_and_tls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production); calls=[]; tls=_FakeTlsRuntime(calls); mcp=_FakeMcpServer(calls=calls); tunnel=_FakeTunnel(start_value=False,calls=calls)
    monkeypatch.setattr(runtime_module,"prove_hms_bridge_runtime_identity",lambda sid:None)
    monkeypatch.setattr(runtime_module,"start_agent_bridge_production_tls",lambda *a:tls)
    runtime=BridgeProductionServiceRuntime(config,assembly,mcp_server_factory=lambda *a:mcp,tunnel_runtime_factory=lambda c, token:tunnel)
    assert runtime.start(threading.Event()) is False
    assert calls.index("tunnel-down") < calls.index("tls-down")
    assert mcp.should_exit is True and runtime.ready is False


def test_wait_detects_tunnel_health_loss_and_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production); tls=_FakeTlsRuntime(); mcp=_FakeMcpServer(); tunnel=_FakeTunnel()
    monkeypatch.setattr(runtime_module,"_TUNNEL_HEALTH_INTERVAL_SECONDS",0.0)
    monkeypatch.setattr(runtime_module,"prove_hms_bridge_runtime_identity",lambda sid:None)
    monkeypatch.setattr(runtime_module,"start_agent_bridge_production_tls",lambda *a:tls)
    runtime=BridgeProductionServiceRuntime(config,assembly,mcp_server_factory=lambda *a:mcp,tunnel_runtime_factory=lambda c, token:tunnel)
    stop=threading.Event(); assert runtime.start(stop); tunnel.fail=True
    with pytest.raises(BridgeProductionServiceRuntimeError,match="secure MCP tunnel failed"): runtime.wait(stop)
    runtime.shutdown()


def test_runtime_with_preexisting_stop_opens_no_listener(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config=_config(tmp_path); assembly=_assembly(config.production)
    monkeypatch.setattr(runtime_module,"start_agent_bridge_production_tls",lambda *a:pytest.fail("pre-stopped runtime must not start TLS"))
    runtime=BridgeProductionServiceRuntime(config,assembly,mcp_server_factory=lambda *a:pytest.fail("pre-stopped runtime must not build MCP"),tunnel_runtime_factory=lambda c, token:pytest.fail("pre-stopped runtime must not build tunnel"))
    stop=threading.Event(); stop.set(); runtime.run(stop)


def test_default_mcp_factory_pins_loopback_and_streamable_http(monkeypatch: pytest.MonkeyPatch) -> None:
    observed={}
    class FakeMcp:
        def streamable_http_app(self,**kwargs):
            observed["app_kwargs"]=dict(kwargs)
            async def app(scope,receive,send): return None
            observed["raw_app"]=app
            return app
    class FakeConfig:
        def __init__(self,**kwargs): observed["uvicorn_config"]=dict(kwargs)
    class FakeServer:
        def __init__(self,config): self.config=config; self.started=False; self.should_exit=False; self.force_exit=False
        def run(self): return
    monkeypatch.setitem(sys.modules,"uvicorn",types.SimpleNamespace(Config=FakeConfig,Server=FakeServer))
    server=_default_mcp_asgi_server_factory(FakeMcp(),"127.0.0.1",8765,_INGRESS_TOKEN)
    assert isinstance(server,FakeServer)
    assert observed["app_kwargs"]=={"host":"127.0.0.1","streamable_http_path":"/mcp","stateless_http":True,"json_response":True}
    protected=observed["uvicorn_config"]["app"]
    assert isinstance(protected,runtime_module.McpTunnelIngressGate)
    assert _INGRESS_TOKEN not in repr(protected)
    expected={"app":protected,"host":"127.0.0.1","port":8765,"log_level":"warning","access_log":False,"lifespan":"on"}
    assert observed["uvicorn_config"]==expected


def test_default_mcp_factory_rejects_non_loopback() -> None:
    with pytest.raises(BridgeProductionServiceRuntimeError,match="exact loopback"):
        _default_mcp_asgi_server_factory(object(),"0.0.0.0",8765,_INGRESS_TOKEN)
