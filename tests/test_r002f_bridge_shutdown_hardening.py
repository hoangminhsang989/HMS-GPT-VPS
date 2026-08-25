import pytest

import hms_gpt_vps.bridge_windows_service_host as host_module
from hms_gpt_vps.bridge_production_service_runtime import (
    BridgeProductionServiceRuntime,
    BridgeProductionServiceRuntimeError,
)


class _TlsRuntime:
    def __init__(self):
        self.shutdown_count = 0

    def shutdown(self):
        self.shutdown_count += 1


def test_runtime_shutdown_surfaces_mcp_error_and_still_closes_tls():
    runtime = object.__new__(BridgeProductionServiceRuntime)
    runtime._closed = False
    runtime._started = True
    runtime._mcp_server = None
    runtime._mcp_thread = None
    runtime._mcp_error = [RuntimeError("mcp failed during shutdown")]
    tls = _TlsRuntime()
    runtime._tls_runtime = tls

    with pytest.raises(
        BridgeProductionServiceRuntimeError,
        match="shutdown failed",
    ):
        runtime.shutdown()

    assert tls.shutdown_count == 1
    assert runtime._closed is True
    assert runtime._started is False


class _Backend:
    def __init__(self):
        self.statuses = []

    def run_dispatcher(self, service_name, service_main):
        service_main()

    def register_control_handler(self, service_name, handler):
        return object()

    def set_service_status(self, handle, status):
        self.statuses.append(status)


class _FatalRuntime:
    def __init__(self):
        self.shutdown_count = 0

    def start(self, stop):
        raise KeyboardInterrupt()

    def wait(self, stop):
        raise AssertionError("wait must not run")

    def shutdown(self):
        self.shutdown_count += 1


def test_service_host_cleans_runtime_before_reraising_fatal_startup(monkeypatch):
    monkeypatch.setattr(
        host_module,
        "prove_hms_bridge_runtime_identity",
        lambda sid: {"process_sid": sid},
    )
    runtime = _FatalRuntime()
    backend = _Backend()
    host = host_module.HmsBridgeWindowsServiceHost(
        backend,
        expected_service_sid="S-1-5-80-1-2-3-4-5",
        runtime_factory=lambda: runtime,
    )

    with pytest.raises(KeyboardInterrupt):
        host.run()

    assert runtime.shutdown_count == 1
    assert backend.statuses[-1].current_state == host_module.SERVICE_STOP_PENDING
