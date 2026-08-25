from dataclasses import dataclass

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
    ran: bool = False
    def run(self, stop):
        self.ran = True


def test_service_host_proves_identity_before_runtime_factory(monkeypatch):
    events = []
    monkeypatch.setattr(module, "prove_hms_bridge_runtime_identity", lambda sid: events.append(("identity", sid)))
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
    assert runtime.ran is True
    assert [s.current_state for s in backend.statuses] == [
        module.SERVICE_START_PENDING,
        module.SERVICE_RUNNING,
        module.SERVICE_STOPPED,
    ]


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
    assert backend.statuses[-1].service_specific_exit_code == module.BRIDGE_SERVICE_FAILURE_IDENTITY
