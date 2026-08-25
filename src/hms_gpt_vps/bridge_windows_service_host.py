from __future__ import annotations

from threading import Event, Lock
from typing import Callable, Protocol

from .agent_windows_service_host import (
    AgentServiceControlBackend,
    AgentServiceStatus,
    ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_SERVICE_SPECIFIC_ERROR,
    NO_ERROR,
    SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP,
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STOPPED,
    SERVICE_STOP_PENDING,
    NativeWindowsServiceControlBackend,
)
from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_NAME,
    prove_hms_bridge_runtime_identity,
    require_hms_bridge_service_sid,
)


BRIDGE_SERVICE_FAILURE_IDENTITY = 110
BRIDGE_SERVICE_FAILURE_RUNTIME_CONSTRUCTION = 120
BRIDGE_SERVICE_FAILURE_RUNTIME_EXECUTION = 130
BRIDGE_SERVICE_FAILURE_HOST_LIFECYCLE = 190


class BridgeServiceRuntime(Protocol):
    def run(self, stop: Event) -> None: ...


BridgeRuntimeFactory = Callable[[], BridgeServiceRuntime]


class HmsBridgeWindowsServiceHost:
    """SCM lifecycle shell that proves low privilege before runtime construction."""

    def __init__(
        self,
        backend: AgentServiceControlBackend,
        *,
        expected_service_sid: str,
        runtime_factory: BridgeRuntimeFactory,
    ) -> None:
        self.backend = backend
        self.expected_service_sid = require_hms_bridge_service_sid(expected_service_sid)
        if not callable(runtime_factory):
            raise TypeError("runtime_factory must be callable")
        self.runtime_factory = runtime_factory
        self.stop = Event()
        self._status_handle: object | None = None
        self._last_status: AgentServiceStatus | None = None
        self._status_lock = Lock()

    def _report(self, status: AgentServiceStatus) -> None:
        status.validate()
        if self._status_handle is None:
            raise RuntimeError("HMSBridge service status handler is not registered")
        with self._status_lock:
            self.backend.set_service_status(self._status_handle, status)
            self._last_status = status

    def _handle_control(self, control: int) -> int:
        if control in {SERVICE_CONTROL_STOP, SERVICE_CONTROL_SHUTDOWN}:
            self.stop.set()
            if self._status_handle is not None:
                try:
                    self._report(
                        AgentServiceStatus(
                            current_state=SERVICE_STOP_PENDING,
                            checkpoint=1,
                            wait_hint_ms=30_000,
                        )
                    )
                except Exception:
                    return ERROR_CALL_NOT_IMPLEMENTED
            return NO_ERROR
        if control == SERVICE_CONTROL_INTERROGATE:
            if self._last_status is not None and self._status_handle is not None:
                try:
                    self.backend.set_service_status(self._status_handle, self._last_status)
                except Exception:
                    return ERROR_CALL_NOT_IMPLEMENTED
            return NO_ERROR
        return ERROR_CALL_NOT_IMPLEMENTED

    def _service_main(self) -> None:
        failure_code = BRIDGE_SERVICE_FAILURE_HOST_LIFECYCLE
        try:
            self._status_handle = self.backend.register_control_handler(
                HMS_BRIDGE_SERVICE_NAME,
                self._handle_control,
            )
            self._report(
                AgentServiceStatus(
                    current_state=SERVICE_START_PENDING,
                    checkpoint=1,
                    wait_hint_ms=30_000,
                )
            )
            # The identity proof MUST precede any runtime factory call because
            # the factory is where production secret/TLS reads will eventually occur.
            failure_code = BRIDGE_SERVICE_FAILURE_IDENTITY
            prove_hms_bridge_runtime_identity(self.expected_service_sid)

            failure_code = BRIDGE_SERVICE_FAILURE_RUNTIME_CONSTRUCTION
            runtime = self.runtime_factory()
            if not callable(getattr(runtime, "run", None)):
                raise TypeError("runtime_factory returned an invalid Bridge runtime")

            if self.stop.is_set():
                failure_code = BRIDGE_SERVICE_FAILURE_HOST_LIFECYCLE
                self._report(
                    AgentServiceStatus(
                        current_state=SERVICE_STOP_PENDING,
                        checkpoint=2,
                        wait_hint_ms=30_000,
                    )
                )
            else:
                self._report(
                    AgentServiceStatus(
                        current_state=SERVICE_RUNNING,
                        controls_accepted=SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                    )
                )
                failure_code = BRIDGE_SERVICE_FAILURE_RUNTIME_EXECUTION
                runtime.run(self.stop)
            failure_code = BRIDGE_SERVICE_FAILURE_HOST_LIFECYCLE
            self._report(AgentServiceStatus(current_state=SERVICE_STOPPED))
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if self._status_handle is not None:
                try:
                    self._report(
                        AgentServiceStatus(
                            current_state=SERVICE_STOPPED,
                            win32_exit_code=ERROR_SERVICE_SPECIFIC_ERROR,
                            service_specific_exit_code=failure_code,
                        )
                    )
                except Exception:
                    pass

    def run(self) -> None:
        self.backend.run_dispatcher(HMS_BRIDGE_SERVICE_NAME, self._service_main)


def run_hms_bridge_windows_service(
    *,
    expected_service_sid: str,
    runtime_factory: BridgeRuntimeFactory,
) -> None:
    HmsBridgeWindowsServiceHost(
        NativeWindowsServiceControlBackend(),
        expected_service_sid=expected_service_sid,
        runtime_factory=runtime_factory,
    ).run()
