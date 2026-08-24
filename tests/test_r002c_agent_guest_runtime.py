from __future__ import annotations

from dataclasses import dataclass
from threading import Event

import pytest

from hms_gpt_vps.agent_connection_epoch_store import AgentConnectionEpochStore
from hms_gpt_vps.agent_device_credential_store import (
    GuestAgentDeviceCredentialStore,
    guest_device_credential_path,
)
from hms_gpt_vps.agent_guest_runtime import (
    AgentGuestRuntime,
    AgentGuestRuntimeConfig,
    AgentRuntimeIdentity,
)
from hms_gpt_vps.agent_runtime_runner import AgentRuntimeRunnerConfig
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentDeviceCredential,
)


def _credential(instance_id: str = "hms-01") -> AgentDeviceCredential:
    return AgentDeviceCredential(
        instance_id=instance_id,
        device_id="device-01",
        secret=b"S" * 32,
    )


def _identity() -> AgentRuntimeIdentity:
    return AgentRuntimeIdentity(
        service_identity=r"NT SERVICE\HMSAgent",
        privilege="non-admin",
    )


def _config(tmp_path) -> AgentGuestRuntimeConfig:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"
    workspace.mkdir()
    state.mkdir()
    return AgentGuestRuntimeConfig(
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=workspace,
        state_root=state,
        health_port=0,
    )


@dataclass
class FakeHttp:
    credential: AgentDeviceCredential
    boot_id: str
    connection_epoch: int
    stop: Event

    def _ack(self) -> dict[str, object]:
        return {
            "schema_version": AGENT_TRANSPORT_SCHEMA_VERSION,
            "accepted": True,
            "instance_id": self.credential.instance_id,
            "device_id": self.credential.device_id,
            "connection_epoch": self.connection_epoch,
        }

    def hello(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
        return self._ack()

    def heartbeat(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
        return self._ack()

    def poll(self, _payload, **_kwargs):  # type: ignore[no-untyped-def]
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


class FakeHealth:
    def __init__(self) -> None:
        self.started = 0
        self.stopped = 0

    def start(self) -> int:
        self.started += 1
        return 8765

    def shutdown(self) -> None:
        self.stopped += 1


def test_guest_runtime_composes_credential_epoch_idempotency_runner_and_health(tmp_path) -> None:
    config = _config(tmp_path)
    credential = _credential()
    store = GuestAgentDeviceCredentialStore(
        guest_device_credential_path(config.state_root),
        protector=lambda data: b"P" + data,
        unprotector=lambda data: data[1:],
    )
    store.save_create_only(credential)

    stop = Event()
    clients: list[tuple[str, int]] = []

    def client_factory(creds, boot_id: str, epoch: int):  # type: ignore[no-untyped-def]
        clients.append((boot_id, epoch))
        return FakeHttp(creds, boot_id, epoch, stop)

    runtime = AgentGuestRuntime.from_guest_state(
        config,
        _identity(),
        credential_store=store,
        boot_id="boot-fixed",
        client_factory=client_factory,
        runner_config=AgentRuntimeRunnerConfig(
            heartbeat_interval_seconds=30.0,
            reconnect_initial_seconds=0.01,
            reconnect_max_seconds=0.02,
            idle_poll_delay_seconds=0.0,
        ),
    )
    fake_health = FakeHealth()
    runtime.health = fake_health  # type: ignore[assignment]

    runtime.run(stop)

    assert fake_health.started == 1
    assert fake_health.stopped == 1
    assert clients == [("boot-fixed", 1)]
    epoch = AgentConnectionEpochStore(
        config.state_root / "agent-connection-epoch.sqlite3"
    ).load()
    assert epoch is not None
    assert epoch.epoch == 1
    assert (config.state_root / "agent-idempotency.sqlite3").is_file()


def test_guest_runtime_health_stops_when_runner_fails_closed(tmp_path) -> None:
    config = _config(tmp_path)

    def client_factory(_creds, _boot_id: str, _epoch: int):  # type: ignore[no-untyped-def]
        raise RuntimeError("fatal factory failure")

    runtime = AgentGuestRuntime(
        config,
        _credential(),
        _identity(),
        boot_id="boot-fixed",
        client_factory=client_factory,
    )
    fake_health = FakeHealth()
    runtime.health = fake_health  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="fatal factory failure"):
        runtime.run(Event())

    assert fake_health.started == 1
    assert fake_health.stopped == 1


def test_guest_runtime_rejects_wrong_instance_before_runtime_store_side_effects(tmp_path) -> None:
    config = _config(tmp_path)

    with pytest.raises(PermissionError, match="another managed instance"):
        AgentGuestRuntime(
            config,
            _credential("hms-02"),
            _identity(),
        )

    assert not (config.state_root / "agent-idempotency.sqlite3").exists()
    assert not (config.state_root / "agent-connection-epoch.sqlite3").exists()


def test_guest_runtime_requires_https_and_existing_managed_paths(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    state = tmp_path / "state"

    invalid_origin = AgentGuestRuntimeConfig(
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="http://bridge.example",
        workspace_root=workspace,
        state_root=state,
    )
    with pytest.raises(ValueError, match="https"):
        invalid_origin.validate()

    missing_paths = AgentGuestRuntimeConfig(
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=workspace,
        state_root=state,
    )
    with pytest.raises(FileNotFoundError, match="workspace root"):
        missing_paths.require_runtime_paths()


@pytest.mark.parametrize(
    ("service_identity", "privilege"),
    [
        (r"NT AUTHORITY\LocalService", "non-admin"),
        (r"NT SERVICE\HMSAgent", "admin"),
    ],
)
def test_runtime_identity_contract_fails_closed(
    service_identity: str,
    privilege: str,
) -> None:
    with pytest.raises(ValueError):
        AgentRuntimeIdentity(
            service_identity=service_identity,
            privilege=privilege,
        ).validate()
