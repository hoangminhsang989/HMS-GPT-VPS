from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from threading import Event, Lock
from typing import Callable, Protocol

from .agent_guest_runtime import AgentGuestRuntime, AgentGuestRuntimeConfig, AgentRuntimeIdentity
from .agent_service_runtime_config import (
    AgentServiceRuntimeConfig,
    load_agent_service_runtime_config,
)
from .agent_windows_identity import (
    IDENTITY_FAILURE_ADMINISTRATORS_PRESENT,
    IDENTITY_FAILURE_NATIVE_INSPECTION,
    IDENTITY_FAILURE_NOT_LOCAL_SERVICE,
    IDENTITY_FAILURE_SERVICE_SID_ABSENT,
    probe_agent_service_identity,
)


HMS_AGENT_SERVICE_NAME = "HMSAgent"

SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_INTERROGATE = 0x00000004
SERVICE_CONTROL_SHUTDOWN = 0x00000005
SERVICE_ACCEPT_STOP = 0x00000001
SERVICE_ACCEPT_SHUTDOWN = 0x00000004

NO_ERROR = 0
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_SERVICE_SPECIFIC_ERROR = 1066

SERVICE_FAILURE_IDENTITY = 10
SERVICE_FAILURE_CONFIG = 20
SERVICE_FAILURE_RUNTIME_CONSTRUCTION = 30
SERVICE_FAILURE_RUNTIME_EXECUTION = 40
SERVICE_FAILURE_HOST_LIFECYCLE = 90
_SAFE_IDENTITY_FAILURE_CODES = frozenset(
    {
        IDENTITY_FAILURE_NATIVE_INSPECTION,
        IDENTITY_FAILURE_NOT_LOCAL_SERVICE,
        IDENTITY_FAILURE_SERVICE_SID_ABSENT,
        IDENTITY_FAILURE_ADMINISTRATORS_PRESENT,
    }
)

_CALLBACK_FACTORY = getattr(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE)
_SERVICE_MAIN_FUNCTION = _CALLBACK_FACTORY(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
_HANDLER_EX_FUNCTION = _CALLBACK_FACTORY(
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
    ctypes.c_void_p,
)


@dataclass(frozen=True)
class AgentServiceStatus:
    current_state: int
    controls_accepted: int = 0
    win32_exit_code: int = NO_ERROR
    service_specific_exit_code: int = 0
    checkpoint: int = 0
    wait_hint_ms: int = 0

    def validate(self) -> None:
        if self.current_state not in {
            SERVICE_STOPPED,
            SERVICE_START_PENDING,
            SERVICE_STOP_PENDING,
            SERVICE_RUNNING,
        }:
            raise ValueError("unsupported HMS Agent service state")
        if self.controls_accepted < 0:
            raise ValueError("controls_accepted must be non-negative")
        if self.current_state != SERVICE_RUNNING and self.controls_accepted != 0:
            raise ValueError("only SERVICE_RUNNING may advertise accepted controls")
        if self.win32_exit_code < 0 or self.service_specific_exit_code < 0:
            raise ValueError("service exit codes must be non-negative")
        if self.checkpoint < 0 or self.wait_hint_ms < 0:
            raise ValueError("service checkpoint/wait hint must be non-negative")
        if self.current_state in {SERVICE_START_PENDING, SERVICE_STOP_PENDING}:
            if self.wait_hint_ms <= 0:
                raise ValueError("pending service states require a positive wait hint")
        elif self.checkpoint != 0 or self.wait_hint_ms != 0:
            raise ValueError("stable service states must clear checkpoint and wait hint")


class AgentServiceControlBackend(Protocol):
    def run_dispatcher(
        self,
        service_name: str,
        service_main: Callable[[], None],
    ) -> None: ...

    def register_control_handler(
        self,
        service_name: str,
        handler: Callable[[int], int],
    ) -> object: ...

    def set_service_status(
        self,
        status_handle: object,
        status: AgentServiceStatus,
    ) -> None: ...


class AgentServiceRuntime(Protocol):
    def run(self, stop: Event) -> None: ...


IdentityProbe = Callable[[], AgentRuntimeIdentity]
ConfigLoader = Callable[[], AgentServiceRuntimeConfig]
RuntimeFactory = Callable[[AgentGuestRuntimeConfig, AgentRuntimeIdentity], AgentServiceRuntime]


def _default_runtime_factory(
    config: AgentGuestRuntimeConfig,
    identity: AgentRuntimeIdentity,
) -> AgentServiceRuntime:
    return AgentGuestRuntime.from_guest_state(config, identity)


def _bounded_identity_failure_code(exc: BaseException) -> int:
    raw = getattr(exc, "safe_service_code", None)
    if isinstance(raw, int) and not isinstance(raw, bool) and raw in _SAFE_IDENTITY_FAILURE_CODES:
        return raw
    return SERVICE_FAILURE_IDENTITY


class AgentWindowsServiceHost:
    """Own the SCM lifecycle around the fail-closed guest Agent runtime."""

    def __init__(
        self,
        backend: AgentServiceControlBackend,
        *,
        service_name: str = HMS_AGENT_SERVICE_NAME,
        identity_probe: IdentityProbe = probe_agent_service_identity,
        config_loader: ConfigLoader = load_agent_service_runtime_config,
        runtime_factory: RuntimeFactory = _default_runtime_factory,
    ) -> None:
        if not service_name.strip():
            raise ValueError("service_name is required")
        self.backend = backend
        self.service_name = service_name
        self.identity_probe = identity_probe
        self.config_loader = config_loader
        self.runtime_factory = runtime_factory
        self.stop = Event()
        self._status_handle: object | None = None
        self._last_status: AgentServiceStatus | None = None
        self._status_lock = Lock()

    def _report(self, status: AgentServiceStatus) -> None:
        status.validate()
        if self._status_handle is None:
            raise RuntimeError("HMS Agent service status handler is not registered")
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
            status = self._last_status
            if status is not None and self._status_handle is not None:
                try:
                    self.backend.set_service_status(self._status_handle, status)
                except Exception:
                    return ERROR_CALL_NOT_IMPLEMENTED
            return NO_ERROR

        return ERROR_CALL_NOT_IMPLEMENTED

    def _service_main(self) -> None:
        failure_code = SERVICE_FAILURE_HOST_LIFECYCLE
        try:
            self._status_handle = self.backend.register_control_handler(
                self.service_name,
                self._handle_control,
            )
            self._report(
                AgentServiceStatus(
                    current_state=SERVICE_START_PENDING,
                    checkpoint=1,
                    wait_hint_ms=30_000,
                )
            )

            failure_code = SERVICE_FAILURE_IDENTITY
            identity = self.identity_probe()

            failure_code = SERVICE_FAILURE_CONFIG
            service_config = self.config_loader()
            guest_config = service_config.to_guest_runtime_config()

            failure_code = SERVICE_FAILURE_RUNTIME_CONSTRUCTION
            runtime = self.runtime_factory(guest_config, identity)

            failure_code = SERVICE_FAILURE_HOST_LIFECYCLE
            if self.stop.is_set():
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
                        controls_accepted=(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN),
                    )
                )
                failure_code = SERVICE_FAILURE_RUNTIME_EXECUTION
                runtime.run(self.stop)

            failure_code = SERVICE_FAILURE_HOST_LIFECYCLE
            self._report(AgentServiceStatus(current_state=SERVICE_STOPPED))
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            report_code = failure_code
            if failure_code == SERVICE_FAILURE_IDENTITY:
                report_code = _bounded_identity_failure_code(exc)
            if self._status_handle is not None:
                try:
                    self._report(
                        AgentServiceStatus(
                            current_state=SERVICE_STOPPED,
                            win32_exit_code=ERROR_SERVICE_SPECIFIC_ERROR,
                            service_specific_exit_code=report_code,
                        )
                    )
                except Exception:
                    pass

    def run(self) -> None:
        self.backend.run_dispatcher(self.service_name, self._service_main)


class _SERVICE_STATUS(ctypes.Structure):
    _fields_ = [
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
    ]


class _SERVICE_TABLE_ENTRY(ctypes.Structure):
    pass


_SERVICE_TABLE_ENTRY._fields_ = [
    ("lpServiceName", wintypes.LPWSTR),
    ("lpServiceProc", _SERVICE_MAIN_FUNCTION),
]


class NativeWindowsServiceControlBackend:
    """Small native SCM adapter used by the packaged Agent service host."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("native Windows service host requires Windows")
        self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._configure_prototypes()
        self._service_main_callback: object | None = None
        self._handler_callback: object | None = None

    def _configure_prototypes(self) -> None:
        self._advapi32.StartServiceCtrlDispatcherW.argtypes = [
            ctypes.POINTER(_SERVICE_TABLE_ENTRY)
        ]
        self._advapi32.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
        self._advapi32.RegisterServiceCtrlHandlerExW.argtypes = [
            wintypes.LPCWSTR,
            _HANDLER_EX_FUNCTION,
            ctypes.c_void_p,
        ]
        self._advapi32.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
        self._advapi32.SetServiceStatus.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_SERVICE_STATUS),
        ]
        self._advapi32.SetServiceStatus.restype = wintypes.BOOL

    @staticmethod
    def _last_error(message: str) -> OSError:
        return OSError(ctypes.get_last_error(), message)

    def run_dispatcher(
        self,
        service_name: str,
        service_main: Callable[[], None],
    ) -> None:
        def native_main(_argc: int, _argv: ctypes.POINTER(wintypes.LPWSTR)) -> None:
            service_main()

        callback = _SERVICE_MAIN_FUNCTION(native_main)
        self._service_main_callback = callback
        table = (_SERVICE_TABLE_ENTRY * 2)()
        table[0].lpServiceName = service_name
        table[0].lpServiceProc = callback
        table[1].lpServiceName = None
        table[1].lpServiceProc = _SERVICE_MAIN_FUNCTION()
        if not self._advapi32.StartServiceCtrlDispatcherW(table):
            raise self._last_error("StartServiceCtrlDispatcherW failed")

    def register_control_handler(
        self,
        service_name: str,
        handler: Callable[[int], int],
    ) -> object:
        def native_handler(
            control: int,
            _event_type: int,
            _event_data: ctypes.c_void_p,
            _context: ctypes.c_void_p,
        ) -> int:
            return int(handler(control))

        callback = _HANDLER_EX_FUNCTION(native_handler)
        self._handler_callback = callback
        handle = self._advapi32.RegisterServiceCtrlHandlerExW(
            service_name,
            callback,
            None,
        )
        if not handle:
            raise self._last_error("RegisterServiceCtrlHandlerExW failed")
        return handle

    def set_service_status(
        self,
        status_handle: object,
        status: AgentServiceStatus,
    ) -> None:
        status.validate()
        native = _SERVICE_STATUS(
            dwServiceType=SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState=status.current_state,
            dwControlsAccepted=status.controls_accepted,
            dwWin32ExitCode=status.win32_exit_code,
            dwServiceSpecificExitCode=status.service_specific_exit_code,
            dwCheckPoint=status.checkpoint,
            dwWaitHint=status.wait_hint_ms,
        )
        if not self._advapi32.SetServiceStatus(
            wintypes.HANDLE(status_handle),
            ctypes.byref(native),
        ):
            raise self._last_error("SetServiceStatus failed")
