from __future__ import annotations

from types import SimpleNamespace
import threading

import pytest

from hms_gpt_vps.bridge_pairing_surface_runtime import (
    BridgePairingSurfaceRuntime,
    BridgePairingSurfaceRuntimeError,
)
from hms_gpt_vps.bridge_production_service_runtime import BridgeProductionServiceRuntime
from hms_gpt_vps.pairing_readiness_runtime import PairingReadinessRuntime


_SERVICE_SID = "S-1-5-80-1-2-3-4-5"


class _FakeReadiness(PairingReadinessRuntime):
    def __init__(self) -> None:
        pass


class _FakeInner(BridgeProductionServiceRuntime):
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.assembly = SimpleNamespace(readiness=_FakeReadiness())
        self._ready_for_test = False
        self.shutdown_count = 0

    @property
    def ready(self) -> bool:
        return self._ready_for_test

    def start(self, stop: threading.Event) -> bool:
        self.events.append("inner.start")
        if stop.is_set():
            return False
        self._ready_for_test = True
        return True

    def wait(self, stop: threading.Event) -> None:
        self.events.append("inner.wait")
        if not stop.is_set():
            stop.wait(0.01)

    def shutdown(self) -> None:
        self.events.append("inner.shutdown")
        self.shutdown_count += 1
        self._ready_for_test = False


class _FakeIpc:
    def __init__(self, events: list[str], *, ready: bool = True) -> None:
        self.events = events
        self._ready = ready
        self._alive = ready
        self._error = None
        self.shutdown_count = 0

    @property
    def ready(self) -> bool:
        return self._ready

    @property
    def alive(self) -> bool:
        return self._alive

    @property
    def error(self):
        return self._error

    def shutdown(self) -> None:
        self.events.append("ipc.shutdown")
        self.shutdown_count += 1
        self._ready = False
        self._alive = False


def test_wrapper_gates_readiness_on_inner_and_pairing_ipc() -> None:
    events: list[str] = []
    inner = _FakeInner(events)
    ipc = _FakeIpc(events)

    def factory(readiness, sid, fatal_stop):
        events.append("ipc.start")
        assert isinstance(readiness, _FakeReadiness)
        assert sid == _SERVICE_SID
        assert isinstance(fatal_stop, threading.Event)
        return ipc

    runtime = BridgePairingSurfaceRuntime(inner, _SERVICE_SID, ipc_factory=factory)
    stop = threading.Event()
    assert runtime.start(stop) is True
    assert runtime.ready is True
    assert events == ["inner.start", "ipc.start"]

    stop.set()
    runtime.wait(stop)
    runtime.shutdown()
    assert events == [
        "inner.start",
        "ipc.start",
        "inner.wait",
        "ipc.shutdown",
        "inner.shutdown",
    ]


def test_wrapper_closes_inner_when_pairing_ipc_is_not_ready() -> None:
    events: list[str] = []
    inner = _FakeInner(events)
    ipc = _FakeIpc(events, ready=False)
    runtime = BridgePairingSurfaceRuntime(
        inner,
        _SERVICE_SID,
        ipc_factory=lambda readiness, sid, stop: ipc,
    )
    with pytest.raises(
        BridgePairingSurfaceRuntimeError,
        match="exact readiness",
    ):
        runtime.start(threading.Event())
    assert inner.shutdown_count == 1
    assert ipc.shutdown_count == 1


def test_pairing_ipc_fatal_error_stops_service_and_wait_fails_closed() -> None:
    events: list[str] = []
    inner = _FakeInner(events)
    stop = threading.Event()
    ipc = _FakeIpc(events)

    def factory(readiness, sid, fatal_stop):
        assert fatal_stop is stop
        return ipc

    runtime = BridgePairingSurfaceRuntime(
        inner,
        _SERVICE_SID,
        ipc_factory=factory,
    )
    assert runtime.start(stop) is True
    ipc._error = RuntimeError("pipe failed")
    ipc._ready = False
    ipc._alive = False
    stop.set()
    with pytest.raises(
        BridgePairingSurfaceRuntimeError,
        match="pairing surface runtime is not ready",
    ):
        runtime.wait(stop)
    runtime.shutdown()
    assert inner.shutdown_count == 1


def test_shutdown_still_closes_inner_when_ipc_shutdown_fails() -> None:
    events: list[str] = []
    inner = _FakeInner(events)

    class BrokenIpc(_FakeIpc):
        def shutdown(self) -> None:
            self.events.append("ipc.shutdown")
            raise RuntimeError("pipe shutdown failed")

    ipc = BrokenIpc(events)
    runtime = BridgePairingSurfaceRuntime(
        inner,
        _SERVICE_SID,
        ipc_factory=lambda readiness, sid, stop: ipc,
    )
    assert runtime.start(threading.Event()) is True
    with pytest.raises(
        BridgePairingSurfaceRuntimeError,
        match="shutdown failed",
    ):
        runtime.shutdown()
    assert inner.shutdown_count == 1
    assert events[-2:] == ["ipc.shutdown", "inner.shutdown"]
