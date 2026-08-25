from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Address, IPv4Network
import socket
import ssl
import threading

from .agent_bridge_http_boundary import (
    AgentBridgeHttpBoundary,
    AgentBridgeHttpRequest,
    AgentBridgeHttpResponse,
)
from .agent_transport_protocol import MAX_AGENT_BODY_BYTES
from .hyperv_network import HyperVNetworkConfig


_DEFAULT_AGENT_TLS_PORT = 9443
_DEFAULT_REQUEST_TIMEOUT_SECONDS = 30
_MAX_REQUEST_TIMEOUT_SECONDS = 120
_PRIVATE_IPV4_NETWORKS = (
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
)


class AgentBridgeTlsServerError(RuntimeError):
    pass


class AgentBridgeTlsHttpShapeError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentBridgeTlsServerConfig:
    network: HyperVNetworkConfig
    port: int = _DEFAULT_AGENT_TLS_PORT
    request_timeout_seconds: int = _DEFAULT_REQUEST_TIMEOUT_SECONDS

    def validate(self) -> None:
        if not isinstance(self.network, HyperVNetworkConfig):
            raise TypeError("network must be a HyperVNetworkConfig")
        self.network.validate()

        subnet = IPv4Network(self.network.subnet, strict=True)
        gateway = IPv4Address(self.network.gateway)
        guest = IPv4Address(self.network.guest_ipv4)
        if not any(subnet.subnet_of(private) for private in _PRIVATE_IPV4_NETWORKS):
            raise ValueError("Agent Bridge TLS subnet must be RFC1918 private IPv4")
        if gateway not in subnet or guest not in subnet:
            raise ValueError("Agent Bridge TLS endpoints must be inside managed subnet")
        if gateway == guest:
            raise ValueError("Agent Bridge TLS host and guest addresses must differ")
        for address, label in ((gateway, "gateway"), (guest, "guest_ipv4")):
            if (
                address.is_unspecified
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
            ):
                raise ValueError(
                    f"Agent Bridge TLS {label} is not an allowed private address"
                )
        if str(gateway) != self.network.gateway:
            raise ValueError("Agent Bridge TLS gateway must use canonical IPv4 text")
        if str(guest) != self.network.guest_ipv4:
            raise ValueError("Agent Bridge TLS guest_ipv4 must use canonical IPv4 text")
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError("Agent Bridge TLS port must be an integer")
        if not 1 <= self.port <= 65535:
            raise ValueError("Agent Bridge TLS port must be between 1 and 65535")
        if (
            not isinstance(self.request_timeout_seconds, int)
            or isinstance(self.request_timeout_seconds, bool)
        ):
            raise ValueError("Agent Bridge TLS request timeout must be an integer")
        if not 1 <= self.request_timeout_seconds <= _MAX_REQUEST_TIMEOUT_SECONDS:
            raise ValueError("Agent Bridge TLS request timeout is outside allowed bounds")

    @property
    def bind_host(self) -> str:
        self.validate()
        return str(IPv4Address(self.network.gateway))

    @property
    def allowed_guest_ipv4(self) -> str:
        self.validate()
        return str(IPv4Address(self.network.guest_ipv4))


def _validate_server_tls_context(context: ssl.SSLContext) -> None:
    if not isinstance(context, ssl.SSLContext):
        raise TypeError("ssl_context must be an ssl.SSLContext")
    if context.protocol != ssl.PROTOCOL_TLS_SERVER:
        raise ValueError("Agent Bridge TLS context must use PROTOCOL_TLS_SERVER")
    minimum = context.minimum_version
    if minimum in {
        ssl.TLSVersion.MINIMUM_SUPPORTED,
        ssl.TLSVersion.SSLv3,
        ssl.TLSVersion.TLSv1,
        ssl.TLSVersion.TLSv1_1,
    }:
        raise ValueError("Agent Bridge TLS context must require TLS 1.2 or newer")
    if minimum < ssl.TLSVersion.TLSv1_2:
        raise ValueError("Agent Bridge TLS context must require TLS 1.2 or newer")


def _raw_header_occurrences(headers: object) -> tuple[tuple[str, str], ...]:
    raw_items = getattr(headers, "raw_items", None)
    if not callable(raw_items):
        raise AgentBridgeTlsHttpShapeError(
            "HTTP parser did not preserve raw header occurrences"
        )
    items = tuple(raw_items())
    for item in items:
        if not isinstance(item, tuple) or len(item) != 2:
            raise AgentBridgeTlsHttpShapeError("HTTP header occurrence is invalid")
        name, value = item
        if not isinstance(name, str) or not isinstance(value, str):
            raise AgentBridgeTlsHttpShapeError("HTTP headers must be text")
    return items


def _declared_body_length(headers: tuple[tuple[str, str], ...]) -> int:
    transfer_encoding = [
        value for name, value in headers if name.casefold() == "transfer-encoding"
    ]
    if transfer_encoding:
        raise AgentBridgeTlsHttpShapeError("Transfer-Encoding is unsupported")

    lengths = [
        value for name, value in headers if name.casefold() == "content-length"
    ]
    if len(lengths) != 1:
        raise AgentBridgeTlsHttpShapeError(
            "exactly one Content-Length header is required"
        )
    value = lengths[0]
    if (
        value != value.strip()
        or not value.isascii()
        or not value.isdecimal()
        or len(value) > 10
    ):
        raise AgentBridgeTlsHttpShapeError("Content-Length is invalid")
    length = int(value)
    if value != str(length):
        raise AgentBridgeTlsHttpShapeError("Content-Length must use canonical decimal")
    if length < 1:
        raise AgentBridgeTlsHttpShapeError("request body must not be empty")
    if length > MAX_AGENT_BODY_BYTES:
        raise OverflowError("request body exceeds Agent transport bound")
    return length


def _fixed_response(status_code: int, body: bytes) -> AgentBridgeHttpResponse:
    return AgentBridgeHttpResponse(
        status_code=status_code,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Cache-Control": "no-store",
        },
        body=body,
    )


_INVALID_HTTP = _fixed_response(400, b'{"error":"invalid_http_request"}')
_TOO_LARGE = _fixed_response(413, b'{"error":"request_too_large"}')
_METHOD_NOT_ALLOWED = _fixed_response(405, b'{"error":"method_not_allowed"}')
_EXPECTATION_FAILED = _fixed_response(417, b'{"error":"expectation_failed"}')


class _AgentBridgeTlsHandler(BaseHTTPRequestHandler):
    server_version = "HMSAgentBridge/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_response(self, response: AgentBridgeHttpResponse) -> None:
        self.close_connection = True
        try:
            self.send_response_only(response.status_code)
            for key, value in response.headers.items():
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response.body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            return

    def handle_expect_100(self) -> bool:
        self._write_response(_EXPECTATION_FAILED)
        return False

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        server = self.server
        if not isinstance(server, _AgentBridgeTlsHttpServer):
            self._write_response(_INVALID_HTTP)
            return
        try:
            raw_headers = _raw_header_occurrences(self.headers)
            length = _declared_body_length(raw_headers)
        except OverflowError:
            self._write_response(_TOO_LARGE)
            return
        except AgentBridgeTlsHttpShapeError:
            self._write_response(_INVALID_HTTP)
            return

        try:
            body = self.rfile.read(length)
        except (TimeoutError, socket.timeout, ssl.SSLError, OSError):
            self._write_response(_INVALID_HTTP)
            return
        if len(body) != length:
            self._write_response(_INVALID_HTTP)
            return

        response = server.boundary.handle(
            AgentBridgeHttpRequest(
                method="POST",
                path=self.path,
                headers=raw_headers,
                body=body,
            )
        )
        self._write_response(response)

    def _method_not_allowed(self) -> None:
        self._write_response(_METHOD_NOT_ALLOWED)

    do_GET = _method_not_allowed
    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_HEAD = _method_not_allowed
    do_OPTIONS = _method_not_allowed
    do_TRACE = _method_not_allowed


class _AgentBridgeTlsHttpServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    address_family = socket.AF_INET

    def __init__(
        self,
        server_address: tuple[str, int],
        boundary: AgentBridgeHttpBoundary,
        ssl_context: ssl.SSLContext,
        *,
        allowed_guest_ipv4: str,
        request_timeout_seconds: int,
    ) -> None:
        self.boundary = boundary
        self.ssl_context = ssl_context
        self.allowed_guest_ipv4 = allowed_guest_ipv4
        self.request_timeout_seconds = request_timeout_seconds
        super().__init__(server_address, _AgentBridgeTlsHandler)

    def get_request(self):  # type: ignore[no-untyped-def]
        raw_socket, client_address = self.socket.accept()
        try:
            if (
                not isinstance(client_address, tuple)
                or len(client_address) < 2
                or client_address[0] != self.allowed_guest_ipv4
            ):
                raise PermissionError(
                    "Agent Bridge TLS rejected unapproved source IPv4"
                )
            raw_socket.settimeout(self.request_timeout_seconds)
            tls_socket = self.ssl_context.wrap_socket(
                raw_socket,
                server_side=True,
            )
            return tls_socket, client_address
        except Exception:
            raw_socket.close()
            raise

    def handle_error(self, request, client_address) -> None:  # type: ignore[no-untyped-def]
        return


class AgentBridgeTlsServer:
    """TLS-only host listener for authenticated outbound Agent requests.

    The listener binds exactly to the managed Hyper-V host gateway and accepts
    TCP only from the configured managed guest IPv4. Every accepted socket is
    upgraded to TLS before ``BaseHTTPRequestHandler`` can parse HTTP.
    """

    def __init__(
        self,
        boundary: AgentBridgeHttpBoundary,
        config: AgentBridgeTlsServerConfig,
        ssl_context: ssl.SSLContext,
    ) -> None:
        if not isinstance(boundary, AgentBridgeHttpBoundary):
            raise TypeError("boundary must be an AgentBridgeHttpBoundary")
        if not isinstance(config, AgentBridgeTlsServerConfig):
            raise TypeError("config must be an AgentBridgeTlsServerConfig")
        config.validate()
        _validate_server_tls_context(ssl_context)
        self.boundary = boundary
        self.config = config
        self.ssl_context = ssl_context
        self._server: _AgentBridgeTlsHttpServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_address(self) -> tuple[str, int] | None:
        server = self._server
        if server is None:
            return None
        host, port = server.server_address[:2]
        return str(host), int(port)

    def start(self) -> tuple[str, int]:
        if self._server is not None:
            raise AgentBridgeTlsServerError("Agent Bridge TLS server is already started")
        try:
            server = _AgentBridgeTlsHttpServer(
                (self.config.bind_host, self.config.port),
                self.boundary,
                self.ssl_context,
                allowed_guest_ipv4=self.config.allowed_guest_ipv4,
                request_timeout_seconds=self.config.request_timeout_seconds,
            )
        except OSError as exc:
            raise AgentBridgeTlsServerError(
                "Agent Bridge TLS listener could not bind managed host gateway"
            ) from exc
        actual_host, actual_port = server.server_address[:2]
        if str(actual_host) != self.config.bind_host or int(actual_port) != self.config.port:
            server.server_close()
            raise AgentBridgeTlsServerError(
                "Agent Bridge TLS listener did not bind exact configured authority"
            )
        thread = threading.Thread(
            target=server.serve_forever,
            name="HMSAgentBridgeTLS",
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
        return str(actual_host), int(actual_port)

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
                raise AgentBridgeTlsServerError(
                    "Agent Bridge TLS server thread did not stop cleanly"
                )

    def __enter__(self) -> "AgentBridgeTlsServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()
