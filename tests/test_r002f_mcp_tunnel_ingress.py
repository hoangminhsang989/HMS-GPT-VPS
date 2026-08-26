from __future__ import annotations

import asyncio

import pytest

import hms_gpt_vps.mcp_tunnel_ingress as module


TOKEN = "a" * 64


def _run_gate(*, path="/mcp", headers=None, token=TOKEN):
    dispatched = []
    sent = []

    async def app(scope, receive, send):
        dispatched.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    gate = module.McpTunnelIngressGate(app, token=token)
    scope = {"type": "http", "path": path, "headers": list(headers or [])}
    asyncio.run(gate(scope, receive, send))
    return gate, dispatched, sent


def test_token_generation_and_repr_never_expose_capability(monkeypatch):
    monkeypatch.setattr(module.secrets, "token_hex", lambda size: "b" * (size * 2))
    assert module.generate_mcp_tunnel_ingress_token() == "b" * 64
    gate, _, _ = _run_gate(path="/.well-known/oauth-protected-resource")
    assert TOKEN not in repr(gate)
    for bad in ("", "A" * 64, "a" * 63, "g" * 64, True, None):
        with pytest.raises(module.McpTunnelIngressError):
            module.require_mcp_tunnel_ingress_token(bad)  # type: ignore[arg-type]


def test_child_environment_uses_upstream_env_indirection_without_token_in_header_spec():
    child = module.build_mcp_tunnel_ingress_child_environment(
        {"CONTROL_PLANE_TUNNEL_ID": "tunnel_" + "1" * 32},
        token=TOKEN,
    )
    assert child[module.MCP_TUNNEL_INGRESS_TOKEN_ENV] == TOKEN
    assert child[module.MCP_EXTRA_HEADERS_ENV] == (
        "X-HMS-Tunnel-Ingress: env:HMS_TUNNEL_INGRESS_TOKEN"
    )
    assert TOKEN not in child[module.MCP_EXTRA_HEADERS_ENV]
    for conflicting in (
        {"HMS_TUNNEL_INGRESS_TOKEN": "old"},
        {"mcp_extra_headers": "old"},
    ):
        with pytest.raises(module.McpTunnelIngressError, match="already contains"):
            module.build_mcp_tunnel_ingress_child_environment(conflicting, token=TOKEN)


def test_exact_mcp_path_rejects_missing_wrong_duplicate_or_malformed_capability():
    cases = [
        [],
        [(b"x-hms-tunnel-ingress", b"b" * 64)],
        [
            (b"x-hms-tunnel-ingress", TOKEN.encode()),
            (b"X-HMS-TUNNEL-INGRESS", TOKEN.encode()),
        ],
        [(b"x-hms-tunnel-ingress", b"\xff" * 64)],
    ]
    for headers in cases:
        _, dispatched, sent = _run_gate(headers=headers)
        assert dispatched == []
        assert sent[0]["status"] == 404
        assert sent[1]["body"] == b"not found"
        assert TOKEN.encode() not in repr(sent).encode()


def test_exact_single_capability_reaches_downstream_and_header_name_is_case_insensitive():
    for name in (b"x-hms-tunnel-ingress", b"X-HMS-TUNNEL-INGRESS"):
        _, dispatched, sent = _run_gate(headers=[(name, TOKEN.encode())])
        assert len(dispatched) == 1
        assert sent[0]["status"] == 204


def test_non_mcp_routes_bypass_gate_for_oauth_discovery():
    _, dispatched, sent = _run_gate(
        path="/.well-known/oauth-protected-resource",
        headers=[],
    )
    assert len(dispatched) == 1
    assert sent[0]["status"] == 204
