from __future__ import annotations

from dataclasses import dataclass
import secrets
import time
from typing import Callable, Protocol

from .agent_connection_epoch_store import AgentConnectionEpochStore
from .agent_https_client import (
    AgentHttpsClient,
    AgentHttpsNetworkError,
    AgentHttpsResponseError,
)
from .agent_runtime_session import (
    AgentCommandAmbiguousError,
    AgentRuntimeSession,
    AgentRuntimeSessionConfig,
    CommandExecutor,
)
from .agent_transport_protocol import AgentDeviceCredential
from .idempotency_store import IdempotencyStore


_SAFE_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)


class StopSignal(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


ClientFactory = Callable[[AgentDeviceCredential, str, int], AgentHttpsClient]


@dataclass(frozen=True)
class AgentRuntimeRunnerConfig:
    heartbeat_interval_seconds: float = 30.0
    reconnect_initial_seconds: float = 1.0
    reconnect_max_seconds: float = 60.0
    idle_poll_delay_seconds: float = 0.25

    def validate(self) -> None:
        if not 1.0 <= self.heartbeat_interval_seconds <= 300.0:
            raise ValueError("heartbeat_interval_seconds must be between 1 and 300")
        if not 0.01 <= self.reconnect_initial_seconds <= 60.0:
            raise ValueError("reconnect_initial_seconds must be between 0.01 and 60")
        if not self.reconnect_initial_seconds <= self.reconnect_max_seconds <= 300.0:
            raise ValueError(
                "reconnect_max_seconds must be >= reconnect_initial_seconds and <= 300"
            )
        if not 0.0 <= self.idle_poll_delay_seconds <= 5.0:
            raise ValueError("idle_poll_delay_seconds must be between 0 and 5")


def _validate_boot_id(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError("boot_id is invalid")
    if any(char not in _SAFE_IDENTIFIER_CHARS for char in value):
        raise ValueError("boot_id contains unsupported characters")


class AgentRuntimeRunner:
    """Long-running outbound Agent connection/reconnect coordinator.

    One `boot_id` is stable for the lifetime of this runner/process. Every new
    connection generation atomically allocates a strictly higher persisted
    `connection_epoch`. Only transport failures known to be transient are
    retried. Authentication/schema/identity/ambiguity failures propagate and
    stop the runner fail-closed.
    """

    def __init__(
        self,
        credential: AgentDeviceCredential,
        epoch_store: AgentConnectionEpochStore,
        idempotency: IdempotencyStore,
        executor: CommandExecutor,
        client_factory: ClientFactory,
        *,
        config: AgentRuntimeRunnerConfig | None = None,
        session_config: AgentRuntimeSessionConfig | None = None,
        boot_id: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        credential.validate()
        self.credential = credential
        self.epoch_store = epoch_store
        self.idempotency = idempotency
        self.executor = executor
        self.client_factory = client_factory
        self.config = config or AgentRuntimeRunnerConfig()
        self.config.validate()
        self.session_config = session_config or AgentRuntimeSessionConfig()
        self.session_config.validate()
        self.boot_id = boot_id or secrets.token_urlsafe(16)
        _validate_boot_id(self.boot_id)
        self._monotonic = monotonic

    @staticmethod
    def _is_retryable(exc: BaseException) -> bool:
        if isinstance(exc, AgentHttpsNetworkError):
            return True
        if isinstance(exc, AgentHttpsResponseError):
            return exc.retryable
        return False

    def _wait_or_stop(self, stop: StopSignal, seconds: float) -> bool:
        if stop.is_set():
            return True
        return bool(stop.wait(seconds))

    def run(self, stop: StopSignal) -> None:
        backoff = self.config.reconnect_initial_seconds

        while not stop.is_set():
            epoch_record = self.epoch_store.allocate_next(
                instance_id=self.credential.instance_id,
                device_id=self.credential.device_id,
            )
            http = self.client_factory(
                self.credential,
                self.boot_id,
                epoch_record.epoch,
            )
            session = AgentRuntimeSession(
                http,
                self.idempotency,
                self.executor,
                config=self.session_config,
            )
            generation_had_successful_cycle = False

            try:
                session.hello()
                next_heartbeat = (
                    self._monotonic() + self.config.heartbeat_interval_seconds
                )

                while not stop.is_set():
                    now_monotonic = self._monotonic()
                    if now_monotonic >= next_heartbeat:
                        session.heartbeat()
                        generation_had_successful_cycle = True
                        backoff = self.config.reconnect_initial_seconds
                        next_heartbeat = (
                            self._monotonic()
                            + self.config.heartbeat_interval_seconds
                        )

                    result = session.poll_once()
                    generation_had_successful_cycle = True
                    backoff = self.config.reconnect_initial_seconds

                    if result is None and self.config.idle_poll_delay_seconds > 0:
                        if self._wait_or_stop(
                            stop,
                            self.config.idle_poll_delay_seconds,
                        ):
                            return

            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                if isinstance(exc, AgentCommandAmbiguousError):
                    raise
                if not self._is_retryable(exc):
                    raise

                delay = (
                    self.config.reconnect_initial_seconds
                    if generation_had_successful_cycle
                    else backoff
                )
                if self._wait_or_stop(stop, delay):
                    return
                if generation_had_successful_cycle:
                    backoff = self.config.reconnect_initial_seconds
                else:
                    backoff = min(
                        self.config.reconnect_max_seconds,
                        max(
                            self.config.reconnect_initial_seconds,
                            backoff * 2.0,
                        ),
                    )
