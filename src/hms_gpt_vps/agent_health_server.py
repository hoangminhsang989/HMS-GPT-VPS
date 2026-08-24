from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import Any

from .agent_health_contract import (
    AGENT_HEALTH_SCHEMA_VERSION,
    DEFAULT_REQUIRED_CAPABILITIES,
    AgentHealthExpectation,
    parse_agent_health,
)


class AgentHealthServerError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentHealthState:
    instance_id: str
    agent_version: str
    workspace_root: str
    boot_id: str
    service_identity: str
    privilege: str
    capabilities: tuple[str, ...] = tuple(sorted(DEFAULT_REQUIRED_CAPABILITIES))

    def to_document(self) -> dict[str, Any]:
        document: dict[str, Any] = {
            "schema_version": AGENT_HEALTH_SCHEMA_VERSION,
            "status": "ok",
            "instance_id": self.instance_id,
            "agent_version": self.agent_version,
            "workspace_root": self.workspace_root,
            "capabilities": list(self.capabilities),
            "service_identity": self.service_identity,
            "listener_scope": "loopback-only",
            "privilege": self.privilege,
            "boot_id": self.boot_id,
        }
        parse_agent_health(
            document,
            AgentHealthExpectation(
                instance_id=self.instance_id,
                workspace_root=self.workspace_root,
                required_capabilities=frozenset(self.capabilities),
            ),
        )
        if frozenset(self.capabilities) != frozenset(DEFAULT_REQUIRED_CAPABILITIES):
            raise AgentHealthServerError(
                "health capabilities must match the canonical Agent capability set"
            )
        return document


@dataclass(frozen=True)
class AgentHealthServerConfig:
    host: str = "127.0.0.1"
    port: int = 8765

    def validate(self) -> None:
        if self.host != "127.0.0.1":
            raise ValueError("Agent health server must bind to IPv4 loopback only")
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError("Agent health server port must be an integer")
        if not 0 <= self.port <= 65535:
            raise ValueError("Agent health server port is outside valid bounds")


class _HealthHandler(BaseHTTPRequestHandler):
    server_version = "HMSAgentHealth/1"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        # Local health probing is deliberately quiet; request metadata is not a
        # substitute for the append-only Agent audit log.
        return

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        server = self.server
        if not isinstance(server, _HealthHttpServer):
            self.send_error(500)
            return

        if self.path != "/healthz":
            self.send_response(404)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        body = server.health_body
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.send_response(405)
        self.send_header("Allow", "GET")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()


class _HealthHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        health_body: bytes,
    ) -> None:
        self.health_body = health_body
        super().__init__(server_address, _HealthHandler)


class AgentHealthServer:
    """Serve one immutable, validated `/healthz` document on loopback only."""

    def __init__(
        self,
        state: AgentHealthState,
        *,
        config: AgentHealthServerConfig | None = None,
    ) -> None:
        self.state = state
        self.config = config or AgentHealthServerConfig()
        self.config.validate()
        document = state.to_document()
        self._body = json.dumps(
            document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        self._server: _HealthHttpServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int | None:
        if self._server is None:
            return None
        return int(self._server.server_address[1])

    def start(self) -> int:
        if self._server is not None:
            raise AgentHealthServerError("Agent health server is already started")
        server = _HealthHttpServer(
            (self.config.host, self.config.port),
            self._body,
        )
        thread = threading.Thread(
            target=server.serve_forever,
            name="HMSAgentHealth",
            daemon=True,
        )
        self._server = server
        self._thread = thread
        try:
            thread.start()
        except Exception:
            self._server = None
            self._thread = None
            server.server_close()
            raise
        return int(server.server_address[1])

    def shutdown(self) -> None:
        server = self._server
        thread = self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5.0)
            if thread.is_alive():
                raise AgentHealthServerError(
                    "Agent health server thread did not stop cleanly"
                )

    def __enter__(self) -> "AgentHealthServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()
