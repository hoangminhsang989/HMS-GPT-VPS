from __future__ import annotations

from datetime import datetime, timezone
import io
import json
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit

import pytest

from hms_gpt_vps.agent_https_client import (
    AgentHttpsClient,
    AgentHttpsClientConfig,
    AgentHttpsNetworkError,
    AgentHttpsResponseError,
    _NoRedirectHandler,
)
from hms_gpt_vps.agent_transport_protocol import (
    AgentDeviceCredential,
    AgentSignedRequest,
    AgentTransportError,
    verify_agent_request,
)


class FakeHeaders:
    def __init__(self, content_type: str = "application/json") -> None:
        self.content_type = content_type

    def get_content_type(self) -> str:
        return self.content_type

    def get(self, name: str, default: str = "") -> str:
        if name.casefold() == "content-type":
            return self.content_type
        return default


class FakeResponse:
    def __init__(
        self,
        body: bytes = b'{"ok":true}',
        *,
        status: int = 200,
        content_type: str = "application/json",
    ) -> None:
        self.body = body
        self.status = status
        self.headers = FakeHeaders(content_type)
        self.closed = False

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    def __init__(self, response: FakeResponse | None = None, error: Exception | None = None) -> None:
        self.response = response or FakeResponse()
        self.error = error
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout: int):  # type: ignore[no-untyped-def]
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        return self.response


def credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )


def client(opener: FakeOpener, **config_kwargs) -> AgentHttpsClient:
    return AgentHttpsClient(
        AgentHttpsClientConfig(
            bridge_origin="https://bridge.example.test:9443",
            **config_kwargs,
        ),
        credential(),
        boot_id="boot-01",
        connection_epoch=3,
        opener=opener,
    )


@pytest.mark.parametrize(
    "origin",
    [
        "http://bridge.example.test",
        "https://user:pass@bridge.example.test",
        "https://bridge.example.test/base",
        "https://bridge.example.test/?token=x",
        "https://bridge.example.test/#fragment",
        "https:///missing-host",
    ],
)
def test_bridge_origin_rejects_downgrade_credentials_and_url_state(origin: str) -> None:
    with pytest.raises(ValueError):
        AgentHttpsClientConfig(bridge_origin=origin).validate()


def test_origin_normalization_keeps_only_https_authority() -> None:
    assert (
        AgentHttpsClientConfig(
            bridge_origin="https://bridge.example.test:443/"
        ).normalized_origin
        == "https://bridge.example.test"
    )


def test_redirect_handler_never_follows_location() -> None:
    handler = _NoRedirectHandler()
    assert handler.redirect_request(None, None, 302, "Found", {}, "https://evil.test") is None


def test_default_client_rejects_non_verifying_tls_context() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ValueError, match="TLS context"):
        AgentHttpsClient(
            AgentHttpsClientConfig(bridge_origin="https://bridge.example.test"),
            credential(),
            boot_id="boot-01",
            connection_epoch=1,
            ssl_context=context,
        )


def test_heartbeat_posts_fixed_signed_json_and_signature_verifies() -> None:
    opener = FakeOpener(FakeResponse(b'{"accepted":true}'))
    fixed = datetime(2026, 8, 23, 11, 30, tzinfo=timezone.utc)
    http = client(opener, timeout_seconds=17)

    result = http.heartbeat(
        {"status": "healthy", "capabilities": ["workspace.read"]},
        now=fixed,
    )

    assert result == {"accepted": True}
    assert opener.timeouts == [17]
    request = opener.requests[0]
    assert request.get_method() == "POST"
    assert request.full_url == "https://bridge.example.test:9443/agent/v1/heartbeat"
    assert request.data is not None
    assert request.get_header("Content-type") == "application/json; charset=utf-8"
    assert request.get_header("Cache-control") == "no-store"
    assert credential().secret not in request.data
    assert credential().secret.decode("ascii") not in str(request.header_items())

    parsed = urlsplit(request.full_url)
    verified = verify_agent_request(
        credential(),
        AgentSignedRequest(
            method=request.get_method(),
            path=parsed.path,
            body=request.data,
            headers=dict(request.header_items()),
        ),
        now=fixed,
    )
    assert verified.instance_id == "hms-01"
    assert verified.device_id == "device-01"
    assert verified.boot_id == "boot-01"
    assert verified.connection_epoch == 3


def test_client_convenience_methods_use_only_fixed_agent_endpoints() -> None:
    opener = FakeOpener()
    http = client(opener)

    http.hello({"hello": True})
    http.heartbeat({"heartbeat": True})
    http.poll({"wait_seconds": 1})
    http.submit_result({"request_id": "req-01", "ok": True})

    paths = [urlsplit(request.full_url).path for request in opener.requests]
    assert paths == [
        "/agent/v1/hello",
        "/agent/v1/heartbeat",
        "/agent/v1/poll",
        "/agent/v1/result",
    ]


def test_client_rejects_arbitrary_endpoint_before_network() -> None:
    opener = FakeOpener()
    http = client(opener)
    with pytest.raises(AgentTransportError, match="unsupported"):
        http.post_json("/admin", {"x": 1})
    assert opener.requests == []


def test_response_must_be_bounded_json_object() -> None:
    too_large = FakeOpener(FakeResponse(b"x" * 33))
    with pytest.raises(AgentHttpsResponseError, match="maximum size"):
        client(too_large, max_response_bytes=32).hello({"x": 1})

    wrong_type = FakeOpener(FakeResponse(b"{}", content_type="text/plain"))
    with pytest.raises(AgentHttpsResponseError, match="Content-Type"):
        client(wrong_type).hello({"x": 1})

    array_body = FakeOpener(FakeResponse(b"[]"))
    with pytest.raises(AgentHttpsResponseError, match="JSON object"):
        client(array_body).hello({"x": 1})

    duplicate = FakeOpener(FakeResponse(b'{"ok":true,"ok":false}'))
    with pytest.raises(AgentHttpsResponseError, match="strict JSON"):
        client(duplicate).hello({"x": 1})


def test_http_and_network_errors_do_not_surface_response_or_device_secret() -> None:
    raw_secret = credential().secret.decode("ascii")
    http_error = HTTPError(
        "https://bridge.example.test/agent/v1/hello",
        401,
        "Unauthorized SECRET-RESPONSE-BODY",
        hdrs=None,
        fp=io.BytesIO(b"SECRET-RESPONSE-BODY"),
    )
    with pytest.raises(AgentHttpsResponseError) as captured:
        client(FakeOpener(error=http_error)).hello({"x": 1})
    assert "SECRET-RESPONSE-BODY" not in str(captured.value)
    assert raw_secret not in str(captured.value)
    assert str(captured.value) == "Bridge returned HTTP status 401"

    with pytest.raises(AgentHttpsNetworkError) as captured_network:
        client(FakeOpener(error=URLError("internal-network-detail"))).hello({"x": 1})
    assert "internal-network-detail" not in str(captured_network.value)
    assert raw_secret not in str(captured_network.value)


def test_response_is_closed_on_parse_failure() -> None:
    response = FakeResponse(b"not-json")
    with pytest.raises(AgentHttpsResponseError):
        client(FakeOpener(response)).hello({"x": 1})
    assert response.closed is True
