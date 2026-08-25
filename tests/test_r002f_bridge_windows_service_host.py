from dataclasses import dataclass, field

import hms_gpt_vps.bridge_windows_service_host as module

SID = "S-1-5-80-1-2-3-4-5"


class FakeBackend:
    def __init__(self):
        self.statuses = []
        self.handler = None

    def run_dispatcher(self, service_name, service_main):
        assert service_name == "HMSBridge"
        service_main()

    def register_control_handler(self, service_name, handler):
        self.handler = handler
        return object()

    def set_service_status(self, handle, status):
        self.statuses.append(status)


@dataclass
class Runtime:
    start_ready: bool = True
    fail_start: bool = False
    events: list[str] = field(default_factory=list)

    def start(self, stop):
        self.events.append("start")
        if self.fail_start:
            raise RuntimeError("startup failed")
        return self.start_ready

    def wait(self, stop):
        self.events.append("wait")
        stop.set()

    def shutdown(self):
        self.events.append("shutdown")


def test_service_host_publishes_running_only_after_runtime_start(monkeypatch):
    events = []
    monkeypatch.setattr(
        module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: events.append(("identity", sid)),
    )
    runtime = Runtime()

    def factory():
        events.append(("factory", None))
        return runtime

    backend = FakeBackend()
    module.HmsBridgeWindowsServiceHost(
        backend,
        expected_service_sid=SID,
        runtime_factory=factory,
    ).run()

    assert events == [("identity", SID), ("factory", None)]
    assert runtime.events == ["start", "wait", "shutdown"]
    assert [s.current_state for s in backend.statuses] == [
        module.SERVICE_START_PENDING,
        module.SERVICE_RUNNING,
        module.SERVICE_STOP_PENDING,
        module.SERVICE_STOPPED,
    ]


def test_service_host_never_publishes_running_when_stop_wins_startup(monkeypatch):
    monkeypatch.setattr(
        module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: {"process_sid": sid},
    )
    runtime = Runtime(start_ready=False)
    backend = FakeBackend()
    module.HmsBridgeWindowsServiceHost(
        backend,
        expected_service_sid=SID,
        runtime_factory=lambda: runtime,
    ).run()

    assert runtime.events == ["start", "shutdown"]
    states = [s.current_state for s in backend.statuses]
    assert states == [
        module.SERVICE_START_PENDING,
        module.SERVICE_STOP_PENDING,
        module.SERVICE_STOPPED,
    ]
    assert module.SERVICE_RUNNING not in states


def test_service_host_classifies_runtime_startup_failure(monkeypatch):
    monkeypatch.setattr(
        module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: {"process_sid": sid},
    )
    runtime = Runtime(fail_start=True)
    backend = FakeBackend()
    module.HmsBridgeWindowsServiceHost(
        backend,
        expected_service_sid=SID,
        runtime_factory=lambda: runtime,
    ).run()

    assert runtime.events == ["start", "shutdown"]
    assert [s.current_state for s in backend.statuses] == [
        module.SERVICE_START_PENDING,
        module.SERVICE_STOP_PENDING,
        module.SERVICE_STOPPED,
    ]
    assert (
        backend.statuses[-1].service_specific_exit_code
        == module.BRIDGE_SERVICE_FAILURE_RUNTIME_STARTUP
    )
    assert all(
        status.current_state != module.SERVICE_RUNNING
        for status in backend.statuses
    )


def test_service_host_does_not_construct_runtime_if_identity_fails(monkeypatch):
    def fail(_sid):
        raise PermissionError("blocked")

    monkeypatch.setattr(module, "prove_hms_bridge_runtime_identity", fail)
    calls = []
    backend = FakeBackend()
    module.HmsBridgeWindowsServiceHost(
        backend,
        expected_service_sid=SID,
        runtime_factory=lambda: calls.append(True),
    ).run()

    assert calls == []
    assert (
        backend.statuses[-1].service_specific_exit_code
        == module.BRIDGE_SERVICE_FAILURE_IDENTITY
    )
