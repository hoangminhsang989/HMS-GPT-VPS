from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from threading import Event

import pytest

from hms_gpt_vps.agent_guest_runtime import AgentRuntimeIdentity
from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.agent_windows_service_host import (
    ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_SERVICE_SPECIFIC_ERROR,
    NO_ERROR,
    SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP,
    SERVICE_FAILURE_CONFIG,
    SERVICE_FAILURE_IDENTITY,
    SERVICE_FAILURE_RUNTIME_CONSTRUCTION,
    SERVICE_FAILURE_RUNTIME_EXECUTION,
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STOP_PENDING,
    SERVICE_STOPPED,
    AgentServiceStatus,
    AgentWindowsServiceHost,
    NativeWindowsServiceControlBackend,
)


class FakeBackend:
    def __init__(self) -> None:
        self.handler = None
        self.statuses: list[AgentServiceStatus] = []
        self.events: list[str] = []

    def run_dispatcher(self, service_name, service_main):  # type: ignore[no-untyped-def]
        self.events.append(f"dispatch:{service_name}")
        service_main()

    def register_control_handler(self, service_name, handler):  # type: ignore[no-untyped-def]
        self.events.append(f"register:{service_name}")
        self.handler = handler
        return 123

    def set_service_status(self, status_handle, status):  # type: ignore[no-untyped-def]
        assert status_handle == 123
        self.statuses.append(status)
        self.events.append(f"status:{status.current_state}")


@dataclass
class FakeRuntime:
    events: list[str]
    action: object | None = None

    def run(self, stop: Event) -> None:
        self.events.append("runtime.run")
        if callable(self.action):
            self.action(stop)


def make_service_config(tmp_path: Path) -> AgentServiceRuntimeConfig:
    return AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="hms-01",
        project_id="project-01",
        bridge_origin="https://bridge.example",
        workspace_root=str((tmp_path / "workspace").resolve()),
        state_root=str((tmp_path / "state").resolve()),
        python_executable=str((tmp_path / "tools" / "python.exe").resolve()),
        git_executable=str((tmp_path / "tools" / "git.exe").resolve()),
        health_port=8765,
    )


def identity() -> AgentRuntimeIdentity:
    return AgentRuntimeIdentity(
        service_identity=r"NT SERVICE\HMSAgent",
        privilege="non-admin",
    )


def test_service_host_proves_identity_before_config_and_runtime_creation(tmp_path: Path) -> None:
    backend = FakeBackend()
    order: list[str] = []
    config = make_service_config(tmp_path)

    def identity_probe():  # type: ignore[no-untyped-def]
        order.append("identity")
        return identity()

    def config_loader():  # type: ignore[no-untyped-def]
        order.append("config")
        return config

    def runtime_factory(guest_config, runtime_identity):  # type: ignore[no-untyped-def]
        order.append("runtime_factory")
        assert guest_config.instance_id == "hms-01"
        assert runtime_identity == identity()
        return FakeRuntime(order)

    host = AgentWindowsServiceHost(
        backend,
        identity_probe=identity_probe,
        config_loader=config_loader,
        runtime_factory=runtime_factory,
    )
    host.run()

    assert order == ["identity", "config", "runtime_factory", "runtime.run"]
    assert [status.current_state for status in backend.statuses] == [
        SERVICE_START_PENDING,
        SERVICE_RUNNING,
        SERVICE_STOPPED,
    ]
    assert backend.statuses[1].controls_accepted == (
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    )


def test_identity_failure_stops_before_config_or_credential_runtime(tmp_path: Path) -> None:
    backend = FakeBackend()
    calls: list[str] = []

    def identity_probe():  # type: ignore[no-untyped-def]
        calls.append("identity")
        raise PermissionError("wrong token")

    def config_loader():  # type: ignore[no-untyped-def]
        calls.append("config")
        return make_service_config(tmp_path)

    host = AgentWindowsServiceHost(
        backend,
        identity_probe=identity_probe,
        config_loader=config_loader,
        runtime_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("not reached")),
    )
    host.run()

    assert calls == ["identity"]
    assert [status.current_state for status in backend.statuses] == [
        SERVICE_START_PENDING,
        SERVICE_STOPPED,
    ]
    failed = backend.statuses[-1]
    assert failed.win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR
    assert failed.service_specific_exit_code == SERVICE_FAILURE_IDENTITY


def test_config_failure_has_distinct_safe_phase_code(tmp_path: Path) -> None:
    backend = FakeBackend()

    def config_loader():  # type: ignore[no-untyped-def]
        raise ValueError("config detail must not become an SCM code")

    AgentWindowsServiceHost(
        backend,
        identity_probe=identity,
        config_loader=config_loader,
        runtime_factory=lambda *_args: (_ for _ in ()).throw(AssertionError("not reached")),
    ).run()

    failed = backend.statuses[-1]
    assert failed.current_state == SERVICE_STOPPED
    assert failed.win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR
    assert failed.service_specific_exit_code == SERVICE_FAILURE_CONFIG


def test_runtime_construction_failure_has_distinct_safe_phase_code(tmp_path: Path) -> None:
    backend = FakeBackend()
    config = make_service_config(tmp_path)

    def runtime_factory(*_args):  # type: ignore[no-untyped-def]
        raise PermissionError("credential/tool detail must not become an SCM code")

    AgentWindowsServiceHost(
        backend,
        identity_probe=identity,
        config_loader=lambda: config,
        runtime_factory=runtime_factory,
    ).run()

    failed = backend.statuses[-1]
    assert failed.current_state == SERVICE_STOPPED
    assert failed.win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR
    assert failed.service_specific_exit_code == SERVICE_FAILURE_RUNTIME_CONSTRUCTION


@pytest.mark.parametrize("control", [SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN])
def test_stop_and_shutdown_controls_signal_runtime_and_report_stop_pending(
    tmp_path: Path,
    control: int,
) -> None:
    backend = FakeBackend()
    config = make_service_config(tmp_path)

    def runtime_factory(_guest_config, _identity):  # type: ignore[no-untyped-def]
        def request_stop(stop: Event) -> None:
            assert backend.handler is not None
            assert backend.handler(control) == NO_ERROR
            assert stop.is_set()

        return FakeRuntime([], request_stop)

    host = AgentWindowsServiceHost(
        backend,
        identity_probe=identity,
        config_loader=lambda: config,
        runtime_factory=runtime_factory,
    )
    host.run()

    states = [status.current_state for status in backend.statuses]
    assert states == [
        SERVICE_START_PENDING,
        SERVICE_RUNNING,
        SERVICE_STOP_PENDING,
        SERVICE_STOPPED,
    ]
    assert backend.statuses[2].controls_accepted == 0


def test_interrogate_republishes_current_status_and_unknown_control_is_rejected(tmp_path: Path) -> None:
    backend = FakeBackend()
    config = make_service_config(tmp_path)

    def runtime_factory(_guest_config, _identity):  # type: ignore[no-untyped-def]
        def interrogate(_stop: Event) -> None:
            assert backend.handler is not None
            before = len(backend.statuses)
            assert backend.handler(SERVICE_CONTROL_INTERROGATE) == NO_ERROR
            assert len(backend.statuses) == before + 1
            assert backend.statuses[-1].current_state == SERVICE_RUNNING
            assert backend.handler(9999) == ERROR_CALL_NOT_IMPLEMENTED

        return FakeRuntime([], interrogate)

    AgentWindowsServiceHost(
        backend,
        identity_probe=identity,
        config_loader=lambda: config,
        runtime_factory=runtime_factory,
    ).run()


def test_runtime_failure_reports_service_specific_stopped_error(tmp_path: Path) -> None:
    backend = FakeBackend()
    config = make_service_config(tmp_path)

    class FailingRuntime:
        def run(self, _stop: Event) -> None:
            raise RuntimeError("transport fatal")

    AgentWindowsServiceHost(
        backend,
        identity_probe=identity,
        config_loader=lambda: config,
        runtime_factory=lambda *_args: FailingRuntime(),
    ).run()

    assert [status.current_state for status in backend.statuses] == [
        SERVICE_START_PENDING,
        SERVICE_RUNNING,
        SERVICE_STOPPED,
    ]
    failed = backend.statuses[-1]
    assert failed.win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR
    assert failed.service_specific_exit_code == SERVICE_FAILURE_RUNTIME_EXECUTION


def test_service_status_contract_rejects_controls_during_pending_and_stable_checkpoint() -> None:
    with pytest.raises(ValueError, match="only SERVICE_RUNNING"):
        AgentServiceStatus(
            current_state=SERVICE_START_PENDING,
            controls_accepted=SERVICE_ACCEPT_STOP,
            checkpoint=1,
            wait_hint_ms=1000,
        ).validate()

    with pytest.raises(ValueError, match="clear checkpoint"):
        AgentServiceStatus(
            current_state=SERVICE_RUNNING,
            checkpoint=1,
        ).validate()


@pytest.mark.skipif(os.name == "nt", reason="non-Windows guard only")
def test_native_scm_backend_refuses_non_windows_hosts() -> None:
    with pytest.raises(OSError, match="requires Windows"):
        NativeWindowsServiceControlBackend()


@pytest.mark.skipif(os.name != "nt", reason="native Windows FFI smoke only")
def test_native_scm_backend_loads_advapi32_and_prototypes_on_windows() -> None:
    NativeWindowsServiceControlBackend()
