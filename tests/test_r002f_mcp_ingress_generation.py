from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

import hms_gpt_vps.mcp_tunnel_ingress as ingress
import hms_gpt_vps.secure_mcp_tunnel_runtime as tunnel
from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig

TOKEN = "c" * 64
SID = "S-1-5-80-1-2-3-4-5"
TUNNEL_ID = "tunnel_" + "a" * 32


def test_generation_is_deterministic_canonical_non_secret_derivation():
    generation = ingress.derive_mcp_tunnel_ingress_generation(TOKEN)
    assert len(generation) == 32
    assert generation == generation.lower()
    assert all(char in "0123456789abcdef" for char in generation)
    assert generation == ingress.derive_mcp_tunnel_ingress_generation(TOKEN)
    assert generation != TOKEN[:32]
    with pytest.raises(ingress.McpTunnelIngressError):
        ingress.derive_mcp_tunnel_ingress_generation("C" * 64)


def test_gate_binds_generation_only_after_exact_capability_and_resets_context():
    generation = ingress.derive_mcp_tunnel_ingress_generation(TOKEN)
    observed = []

    async def app(scope, receive, send):
        observed.append(ingress.current_mcp_tunnel_ingress_generation())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    sent = []
    async def send(message):
        sent.append(message)

    gate = ingress.McpTunnelIngressGate(app, token=TOKEN)
    asyncio.run(gate({"type": "http", "path": "/mcp", "headers": [(b"x-hms-tunnel-ingress", TOKEN.encode())]}, receive, send))
    assert observed == [generation]
    assert ingress.current_mcp_tunnel_ingress_generation() is None

    observed.clear(); sent.clear()
    asyncio.run(gate({"type": "http", "path": "/mcp", "headers": [(b"x-hms-tunnel-ingress", b"d" * 64)]}, receive, send))
    assert observed == []
    assert sent[0]["status"] == 404
    assert ingress.current_mcp_tunnel_ingress_generation() is None


def test_gate_context_resets_when_downstream_raises():
    generation = ingress.derive_mcp_tunnel_ingress_generation(TOKEN)

    async def app(scope, receive, send):
        assert ingress.current_mcp_tunnel_ingress_generation() == generation
        raise RuntimeError("downstream failed")

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        return None

    gate = ingress.McpTunnelIngressGate(app, token=TOKEN)
    with pytest.raises(RuntimeError, match="downstream failed"):
        asyncio.run(gate({"type": "http", "path": "/mcp", "headers": [(b"x-hms-tunnel-ingress", TOKEN.encode())]}, receive, send))
    assert ingress.current_mcp_tunnel_ingress_generation() is None


def test_non_mcp_route_never_receives_generation_context():
    observed = []

    async def app(scope, receive, send):
        observed.append(ingress.current_mcp_tunnel_ingress_generation())
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        return None

    gate = ingress.McpTunnelIngressGate(app, token=TOKEN)
    asyncio.run(gate({"type": "http", "path": "/.well-known/oauth-protected-resource", "headers": []}, receive, send))
    assert observed == [None]


def test_tunnel_handshake_attempt_uses_exact_derived_generation(monkeypatch, tmp_path: Path):
    runtime_root = tmp_path / "runtime"; runtime_root.mkdir()
    secret_parent = tmp_path / "secrets"; secret_parent.mkdir()
    install_root = tmp_path / "package"; install_root.mkdir()
    executable = install_root / "tunnel-client-runtime.exe"; executable.write_bytes(b"exe")
    secret = BridgeServiceSecretStorageConfig(secret_parent / "service-runtime", SID)

    class Package:
        def __init__(self, install_root: Path, executable_path: Path) -> None:
            self.install_root = install_root
            self.executable_path = executable_path
        def validate(self): return None

    monkeypatch.setattr(tunnel, "DEFAULT_BRIDGE_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(tunnel, "TunnelRuntimePackageConfig", Package)
    config = tunnel.SecureMcpTunnelRuntimeConfig(
        expected_service_sid=SID, secret_storage=secret, tunnel_id=TUNNEL_ID,
        mcp_ingress_token=TOKEN, package=Package(install_root, executable), runtime_root=runtime_root,
    )
    runtime = tunnel.SecureMcpTunnelRuntime(config)
    url_file = runtime._prepare_handshake()
    generation = ingress.derive_mcp_tunnel_ingress_generation(TOKEN)
    assert url_file.parent.name == "attempt-" + generation
    runtime._cleanup_handshake()
    assert not url_file.parent.exists()
