from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from hms_gpt_vps.agent_connection_registry import AgentPresence
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.pairing_exchange import PairingExchangeKey, PairingSessionExchange
from hms_gpt_vps.pairing_http_service import (
    PAIRING_HTTP_MAX_BODY_BYTES,
    PAIRING_HTTP_SCHEMA_VERSION,
    PairingHttpRequest,
    PairingHttpService,
)
from hms_gpt_vps.pairing_link_lease import PairingLinkLeaseStore
from hms_gpt_vps.pairing_readiness_runtime import (
    PairingReadinessConfig,
    PairingReadinessRuntime,
)
from hms_gpt_vps.pairing_store import PairingStore
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


NOW = datetime(2026, 8, 25, 6, 30, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"
CLIENT_NONCE = "client-nonce-0123456789"


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = None

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("pairing lease missing")
        return self.value

    def clear(self) -> None:
        self.value = None


class PresenceReader:
    def __init__(self, value: AgentPresence | None) -> None:
        self.value = value

    def get_presence(self, instance_id: str) -> AgentPresence | None:
        return self.value


class Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def presence(at: datetime = NOW) -> AgentPresence:
    return AgentPresence(
        instance_id=INSTANCE_ID,
        device_id="device-01",
        boot_id="boot-01",
        connection_epoch=1,
        first_seen_at=at - timedelta(seconds=30),
        last_seen_at=at,
    )


def build_service(tmp_path: Path):
    db_path = tmp_path / "bridge-auth.sqlite3"
    pairing = PairingStore(db_path)
    sessions = ControlSessionStore(db_path)
    provision = ProvisionStateStore(tmp_path / "provision.json")
    provision.transition(
        instance_id=INSTANCE_ID,
        state=ProvisionState.INSTALL_SECRETS_CLEARED,
    )
    secret = MemorySecretStore()
    lease_store = PairingLinkLeaseStore(secret)
    clock = Clock()
    presence_reader = PresenceReader(presence())
    readiness = PairingReadinessRuntime(
        PairingReadinessConfig(
            instance_id=INSTANCE_ID,
            bridge_base_url="https://bridge.example",
        ),
        provision,
        presence_reader,
        pairing,
        lease_store,
        tmp_path / "pairing-issuance.lock",
        clock=clock,
    )
    exchange = PairingSessionExchange(
        pairing,
        sessions,
        PairingExchangeKey(b"K" * 32),
    )
    service = PairingHttpService(readiness, exchange)
    issued = readiness.issue()
    lease = lease_store.load()
    assert lease is not None
    return (
        service,
        readiness,
        pairing,
        sessions,
        clock,
        presence_reader,
        issued,
        lease,
    )


def request_for(
    pair_id: str,
    token: str,
    *,
    nonce: str = CLIENT_NONCE,
    method: str = "POST",
    path: str | None = None,
    content_type: str = "application/json",
    body_override: bytes | None = None,
    extra_headers: dict[str, str] | None = None,
) -> PairingHttpRequest:
    body = (
        body_override
        if body_override is not None
        else json.dumps(
            {
                "schema_version": PAIRING_HTTP_SCHEMA_VERSION,
                "pair_token": token,
                "client_nonce": nonce,
            },
            separators=(",", ":"),
        ).encode("utf-8")
    )
    headers = {
        "Content-Type": content_type,
        "Content-Length": str(len(body)),
    }
    if extra_headers:
        headers.update(extra_headers)
    return PairingHttpRequest(
        method=method,
        path=path or f"/pair/{pair_id}",
        headers=headers,
        body=body,
    )


def response_json(response) -> dict:
    return json.loads(response.body.decode("utf-8"))


def test_success_exchanges_pairing_for_initial_session_without_repr_leak(
    tmp_path: Path,
) -> None:
    service, readiness, _pairing, sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    request = request_for(issued.pair_id, lease.token)
    clock.value = NOW + timedelta(seconds=1)

    response = service.handle(request)
    document = response_json(response)

    assert response.status == 200
    assert response.header("Cache-Control") == "no-store"
    assert response.header("Pragma") == "no-cache"
    assert response.header("Content-Length") == str(len(response.body))
    assert document["schema_version"] == PAIRING_HTTP_SCHEMA_VERSION
    assert document["instance_id"] == INSTANCE_ID
    assert document["session_token"]
    assert lease.token not in repr(request)
    assert document["session_token"] not in repr(response)

    stored = sessions.require(document["session_id"])
    assert stored.instance_id == INSTANCE_ID
    assert stored.token_sha256 != document["session_token"]

    observed = readiness.observe()
    assert observed.pairing_ready is True
    assert observed.paired is True
    assert observed.pair_id == issued.pair_id


def test_same_token_same_nonce_retry_returns_exact_same_session_response(
    tmp_path: Path,
) -> None:
    service, _readiness, _pairing, _sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    request = request_for(issued.pair_id, lease.token)

    clock.value = NOW + timedelta(seconds=1)
    first = service.handle(request)
    clock.value = NOW + timedelta(seconds=30)
    second = service.handle(request)

    assert first.status == 200
    assert second.status == 200
    assert second.body == first.body


def test_wrong_token_returns_generic_secret_free_rejection(tmp_path: Path) -> None:
    service, _readiness, _pairing, _sessions, clock, _presence, issued, _lease = (
        build_service(tmp_path)
    )
    wrong_token = "wrong-secret-token"
    clock.value = NOW + timedelta(seconds=1)
    response = service.handle(request_for(issued.pair_id, wrong_token))

    assert response.status == 401
    assert response_json(response) == {
        "schema_version": PAIRING_HTTP_SCHEMA_VERSION,
        "error": "pairing_rejected",
    }
    assert wrong_token.encode("utf-8") not in response.body


def test_stale_presence_blocks_exchange_before_pairing_is_consumed(tmp_path: Path) -> None:
    service, _readiness, pairing, _sessions, clock, presence_reader, issued, lease = (
        build_service(tmp_path)
    )
    clock.value = NOW + timedelta(seconds=91)
    presence_reader.value = presence(NOW)

    response = service.handle(request_for(issued.pair_id, lease.token))

    assert response.status == 401
    assert pairing.require(issued.pair_id).consumed_at is None


def test_other_pair_id_is_rejected_before_exchange(tmp_path: Path) -> None:
    service, _readiness, pairing, _sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    clock.value = NOW + timedelta(seconds=1)
    response = service.handle(request_for("other-pair", lease.token))

    assert response.status == 401
    assert pairing.require(issued.pair_id).consumed_at is None


@pytest.mark.parametrize(
    "body",
    [
        (
            '{"schema_version":1,"schema_version":1,'
            '"pair_token":"TOKEN","client_nonce":"client-nonce-0123456789"}'
        ).encode("utf-8"),
        (
            '{"schema_version":1,"pair_token":"TOKEN",'
            '"client_nonce":"client-nonce-0123456789","extra":true}'
        ).encode("utf-8"),
        (
            '{"schema_version":true,"pair_token":"TOKEN",'
            '"client_nonce":"client-nonce-0123456789"}'
        ).encode("utf-8"),
    ],
)
def test_strict_json_contract_rejects_duplicate_extra_and_bool_schema(
    tmp_path: Path,
    body: bytes,
) -> None:
    service, _readiness, _pairing, _sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    body = body.replace(b"TOKEN", lease.token.encode("utf-8"))
    clock.value = NOW + timedelta(seconds=1)
    response = service.handle(
        request_for(
            issued.pair_id,
            lease.token,
            body_override=body,
        )
    )

    assert response.status == 400
    assert lease.token.encode("utf-8") not in response.body


def test_method_path_media_type_and_body_bounds_fail_closed(tmp_path: Path) -> None:
    service, _readiness, _pairing, _sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    clock.value = NOW + timedelta(seconds=1)

    method = service.handle(request_for(issued.pair_id, lease.token, method="GET"))
    assert method.status == 405
    assert method.header("Allow") == "POST"

    query = service.handle(
        request_for(
            issued.pair_id,
            lease.token,
            path=f"/pair/{issued.pair_id}?debug=1",
        )
    )
    assert query.status == 404

    media = service.handle(
        request_for(
            issued.pair_id,
            lease.token,
            content_type="text/plain",
        )
    )
    assert media.status == 415

    oversized = b"{" + (b"x" * PAIRING_HTTP_MAX_BODY_BYTES)
    large = service.handle(
        request_for(
            issued.pair_id,
            lease.token,
            body_override=oversized,
        )
    )
    assert large.status == 413


def test_transfer_encoding_and_content_length_mismatch_are_rejected(
    tmp_path: Path,
) -> None:
    service, _readiness, _pairing, _sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    clock.value = NOW + timedelta(seconds=1)

    transfer = service.handle(
        request_for(
            issued.pair_id,
            lease.token,
            extra_headers={"Transfer-Encoding": "chunked"},
        )
    )
    assert transfer.status == 400

    request = request_for(issued.pair_id, lease.token)
    bad_length = PairingHttpRequest(
        method=request.method,
        path=request.path,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(request.body) + 1),
        },
        body=request.body,
    )
    mismatch = service.handle(bad_length)
    assert mismatch.status == 400


def test_recovery_with_different_nonce_is_generic_rejection(tmp_path: Path) -> None:
    service, _readiness, _pairing, _sessions, clock, _presence, issued, lease = (
        build_service(tmp_path)
    )
    clock.value = NOW + timedelta(seconds=1)
    first = service.handle(request_for(issued.pair_id, lease.token))
    assert first.status == 200

    different_nonce = "different-nonce-0123456789"
    clock.value = NOW + timedelta(seconds=10)
    rejected = service.handle(
        request_for(
            issued.pair_id,
            lease.token,
            nonce=different_nonce,
        )
    )

    assert rejected.status == 401
    assert different_nonce.encode("utf-8") not in rejected.body
