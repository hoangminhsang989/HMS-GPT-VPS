from __future__ import annotations

from dataclasses import dataclass

import pytest

from hms_gpt_vps.agent_connection_epoch_store import (
    AgentConnectionEpochError,
    AgentConnectionEpochStore,
)
from hms_gpt_vps.agent_https_client import (
    AgentHttpsNetworkError,
    AgentHttpsResponseError,
)
from hms_gpt_vps.agent_runtime_runner import (
    AgentRuntimeRunner,
    AgentRuntimeRunnerConfig,
)
from hms_gpt_vps.agent_runtime_session import (
    AgentCommandAmbiguousError,
    AgentExecutionResponse,
)
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentDeviceCredential,
)
from hms_gpt_vps.idempotency_store import IdempotencyStore


class FakeStop:
    def __init__(self, *, stop_on_wait_number: int | None = None) -> None:
        self.stopped = False
        self.waits: list[float] = []
        self.stop_on_wait_number = stop_on_wait_number

    def is_set(self) -> bool:
        return self.stopped

    def set(self) -> None:
        self.stopped = True

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(0.0 if timeout is None else float(timeout))
        if (
            self.stop_on_wait_number is not None
            and len(self.waits) >= self.stop_on_wait_number
        ):
            self.stopped = True
        return self.stopped


@dataclass
class FakeHttp:
    credential: AgentDeviceCredential
    boot_id: str
    connection_epoch: int
    stop: FakeStop
    hello_error: BaseException | None = None
    poll_error: BaseException | None = None
    stop_on_poll: bool = False

    def _ack(self) -> dict[str, object]:
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "accepted": True,
            "instance_id": self.credential.instance_id,
            "device_id": self.credential.device_id,
            "connection_epoch": self.connection_epoch,
        }

    def hello(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
        if self.hello_error is not None:
            raise self.hello_error
        return self._ack()

    def heartbeat(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
        return self._ack()

    def poll(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
        if self.poll_error is not None:
            raise self.poll_error
        if self.stop_on_poll:
            self.stop.set()
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "instance_id": self.credential.instance_id,
            "command": None,
        }

    def submit_result(self, payload, **_kwargs):  # type: ignore[no-untyped-def]
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "accepted": True,
            "instance_id": self.credential.instance_id,
            "request_id": payload["request_id"],
        }


def credential() -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id="hms-01",
        device_id="device-01",
        secret=b"S" * 32,
    )


def runner(
    tmp_path,
    stop: FakeStop,
    factory,
    *,
    initial: float = 1.0,
    maximum: float = 4.0,
) -> AgentRuntimeRunner:
    return AgentRuntimeRunner(
        credential(),
        AgentConnectionEpochStore(tmp_path / "epoch.sqlite3"),
        IdempotencyStore(tmp_path / "idempotency.sqlite3"),
        lambda _command: AgentExecutionResponse("ok", {}),
        factory,
        config=AgentRuntimeRunnerConfig(
            heartbeat_interval_seconds=30.0,
            reconnect_initial_seconds=initial,
            reconnect_max_seconds=maximum,
            idle_poll_delay_seconds=0.01,
        ),
        boot_id="boot-fixed",
        monotonic=lambda: 0.0,
    )


def test_network_reconnect_keeps_boot_id_increments_epoch_and_caps_backoff(tmp_path) -> None:
    stop = FakeStop()
    created: list[tuple[str, int]] = []
    hello_errors: list[BaseException | None] = [
        AgentHttpsNetworkError("network"),
        AgentHttpsNetworkError("network"),
        AgentHttpsNetworkError("network"),
        None,
    ]

    def factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        created.append((boot_id, epoch))
        error = hello_errors.pop(0)
        return FakeHttp(
            creds,
            boot_id,
            epoch,
            stop,
            hello_error=error,
            stop_on_poll=error is None,
        )

    runtime = runner(tmp_path, stop, factory, initial=1.0, maximum=2.0)
    runtime.run(stop)

    assert created == [
        ("boot-fixed", 1),
        ("boot-fixed", 2),
        ("boot-fixed", 3),
        ("boot-fixed", 4),
    ]
    assert stop.waits == [1.0, 2.0, 2.0]
    assert AgentConnectionEpochStore(tmp_path / "epoch.sqlite3").load().epoch == 4  # type: ignore[union-attr]


@pytest.mark.parametrize("status", [408, 425, 429, 500, 503, 599])
def test_retryable_http_status_reconnects(status: int, tmp_path) -> None:
    stop = FakeStop()
    epochs: list[int] = []

    def factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        epochs.append(epoch)
        if epoch == 1:
            return FakeHttp(
                creds,
                boot_id,
                epoch,
                stop,
                hello_error=AgentHttpsResponseError(
                    f"Bridge returned HTTP status {status}",
                    status_code=status,
                ),
            )
        return FakeHttp(creds, boot_id, epoch, stop, stop_on_poll=True)

    runner(tmp_path, stop, factory).run(stop)
    assert epochs == [1, 2]
    assert stop.waits == [1.0]


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 403, 404, 409, 422])
def test_nonretryable_http_status_is_fatal(status: int, tmp_path) -> None:
    stop = FakeStop()
    epochs: list[int] = []

    def factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        epochs.append(epoch)
        return FakeHttp(
            creds,
            boot_id,
            epoch,
            stop,
            hello_error=AgentHttpsResponseError(
                f"Bridge returned HTTP status {status}",
                status_code=status,
            ),
        )

    with pytest.raises(AgentHttpsResponseError) as captured:
        runner(tmp_path, stop, factory).run(stop)
    assert captured.value.status_code == status
    assert captured.value.retryable is False
    assert epochs == [1]
    assert stop.waits == []


def test_stop_signal_interrupts_reconnect_wait_without_allocating_new_epoch(tmp_path) -> None:
    stop = FakeStop(stop_on_wait_number=1)
    epochs: list[int] = []

    def factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        epochs.append(epoch)
        return FakeHttp(
            creds,
            boot_id,
            epoch,
            stop,
            hello_error=AgentHttpsNetworkError("network"),
        )

    runner(tmp_path, stop, factory).run(stop)
    assert epochs == [1]
    assert stop.waits == [1.0]


def test_command_ambiguity_is_fatal_and_never_reconnects(tmp_path) -> None:
    stop = FakeStop()
    epochs: list[int] = []

    def factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        epochs.append(epoch)
        return FakeHttp(
            creds,
            boot_id,
            epoch,
            stop,
            poll_error=AgentCommandAmbiguousError("ambiguous"),
        )

    with pytest.raises(AgentCommandAmbiguousError):
        runner(tmp_path, stop, factory).run(stop)
    assert epochs == [1]
    assert stop.waits == []


def test_successful_cycle_resets_reconnect_delay(tmp_path) -> None:
    stop = FakeStop()
    epochs: list[int] = []

    class OneGoodPollThenFail(FakeHttp):
        def __init__(self, *args, **kwargs) -> None:  # type: ignore[no-untyped-def]
            super().__init__(*args, **kwargs)
            self.poll_count = 0

        def poll(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
            self.poll_count += 1
            if self.poll_count == 1:
                return {
                    "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
                    "instance_id": self.credential.instance_id,
                    "command": None,
                }
            raise AgentHttpsNetworkError("network")

    def factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        epochs.append(epoch)
        if epoch == 1:
            return OneGoodPollThenFail(creds, boot_id, epoch, stop)
        return FakeHttp(creds, boot_id, epoch, stop, stop_on_poll=True)

    runtime = runner(tmp_path, stop, factory, initial=1.0, maximum=8.0)
    runtime.run(stop)
    assert epochs == [1, 2]
    assert stop.waits[0] == 0.01
    assert stop.waits[1] == 1.0


def test_epoch_store_never_creates_missing_security_parent(tmp_path) -> None:
    missing_parent = tmp_path / "missing-state"
    store = AgentConnectionEpochStore(missing_parent / "epoch.sqlite3")

    with pytest.raises(AgentConnectionEpochError, match="parent must already exist"):
        store.allocate_next(instance_id="hms-01", device_id="device-01")

    assert missing_parent.exists() is False


def test_http_response_retryable_property_is_status_only() -> None:
    assert AgentHttpsResponseError("x", status_code=503).retryable is True
    assert AgentHttpsResponseError("x", status_code=429).retryable is True
    assert AgentHttpsResponseError("x", status_code=401).retryable is False
    assert AgentHttpsResponseError("x", status_code=302).retryable is False
    assert AgentHttpsResponseError("x").retryable is False
