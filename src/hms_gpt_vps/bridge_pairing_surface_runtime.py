from __future__ import annotations

from dataclasses import dataclass, field
import threading
from typing import Callable, Protocol

from .bridge_pairing_link_ipc import (
    BridgePairingLinkIpcError,
    BridgePairingLinkIpcServer,
    start_pairing_link_ipc_server,
)
from .bridge_production_service_runtime import BridgeProductionServiceRuntime
from .bridge_service_identity import require_hms_bridge_service_sid
from .pairing_readiness_runtime import PairingReadinessRuntime


class BridgePairingSurfaceRuntimeError(RuntimeError):
    pass


class PairingIpcRuntime(Protocol):
    @property
    def ready(self) -> bool: ...
    @property
    def alive(self) -> bool: ...
    @property
    def error(self) -> BaseException | None: ...
    def shutdown(self) -> None: ...


PairingIpcFactory = Callable[
    [PairingReadinessRuntime, str, threading.Event],
    PairingIpcRuntime,
]


@dataclass
class BridgePairingSurfaceRuntime:
    """Attach the local pairing-link pipe to an already assembled Bridge runtime.

    SCM readiness is delayed until the inner TLS/MCP runtime and the protected
    local named-pipe surface are both ready. A fatal pipe failure signals the
    same stop Event owned by the SCM host, so wait() converts that stop into a
    service failure instead of silently continuing without pairing authority.
    """

    inner: BridgeProductionServiceRuntime
    expected_service_sid: str
    ipc_factory: PairingIpcFactory = start_pairing_link_ipc_server
    _ipc: PairingIpcRuntime | None = field(init=False, default=None, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.inner, BridgeProductionServiceRuntime):
            raise TypeError("inner must be BridgeProductionServiceRuntime")
        self.expected_service_sid = require_hms_bridge_service_sid(
            self.expected_service_sid
        )
        if not callable(self.ipc_factory):
            raise TypeError("ipc_factory must be callable")

    @property
    def ready(self) -> bool:
        ipc = self._ipc
        return bool(
            self.inner.ready
            and ipc is not None
            and ipc.ready
            and ipc.alive
            and ipc.error is None
        )

    def start(self, stop: threading.Event) -> bool:
        if not isinstance(stop, threading.Event):
            raise TypeError("stop must be a threading.Event")
        if self._ipc is not None:
            raise BridgePairingSurfaceRuntimeError(
                "pairing surface runtime is already starting or started"
            )
        if not self.inner.start(stop):
            return False
        try:
            readiness = self.inner.assembly.readiness
            if not isinstance(readiness, PairingReadinessRuntime):
                raise BridgePairingSurfaceRuntimeError(
                    "Bridge assembly pairing readiness authority is invalid"
                )
            ipc = self.ipc_factory(readiness, self.expected_service_sid, stop)
            self._ipc = ipc
            if (
                not ipc.ready
                or not ipc.alive
                or ipc.error is not None
                or stop.is_set()
            ):
                raise BridgePairingSurfaceRuntimeError(
                    "pairing IPC did not reach exact readiness"
                )
            return True
        except BaseException:
            try:
                self.shutdown()
            except Exception as shutdown_exc:
                raise BridgePairingSurfaceRuntimeError(
                    "pairing surface startup failed and shutdown also failed"
                ) from shutdown_exc
            raise

    def wait(self, stop: threading.Event) -> None:
        if not isinstance(stop, threading.Event):
            raise TypeError("stop must be a threading.Event")
        if not self.ready:
            raise BridgePairingSurfaceRuntimeError(
                "pairing surface runtime is not ready"
            )
        self.inner.wait(stop)
        ipc = self._ipc
        if ipc is None:
            raise BridgePairingSurfaceRuntimeError(
                "pairing IPC authority disappeared"
            )
        if ipc.error is not None:
            raise BridgePairingSurfaceRuntimeError(
                "pairing IPC failed while HMSBridge was running"
            ) from ipc.error
        # Normal SCM stop sets stop. If inner.wait returned without stop and the
        # pipe is no longer alive, fail closed rather than treating it as clean.
        if not stop.is_set() and not ipc.alive:
            raise BridgePairingSurfaceRuntimeError(
                "pairing IPC exited before SCM stop"
            )

    def shutdown(self) -> None:
        first_error: BaseException | None = None
        ipc = self._ipc
        self._ipc = None
        if ipc is not None:
            try:
                ipc.shutdown()
            except BaseException as exc:
                first_error = exc
        try:
            self.inner.shutdown()
        except BaseException as exc:
            if first_error is None:
                first_error = exc
        if first_error is not None:
            raise BridgePairingSurfaceRuntimeError(
                "pairing surface runtime shutdown failed"
            ) from first_error


def build_bridge_pairing_surface_runtime(
    inner: BridgeProductionServiceRuntime,
    expected_service_sid: str,
) -> BridgePairingSurfaceRuntime:
    return BridgePairingSurfaceRuntime(
        inner=inner,
        expected_service_sid=expected_service_sid,
    )
