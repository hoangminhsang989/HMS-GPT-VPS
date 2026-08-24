from __future__ import annotations

from dataclasses import dataclass

from .agent_health_contract import AgentHealthDocument
from .agent_health_probe import probe_agent_application_health_for_runtime
from .agent_service_install import AgentServiceConfig
from .agent_service_readiness import probe_agent_service_readiness
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .powershell_direct import PowerShellDirectCredential
from .provisioning import ProvisionObservation


@dataclass(frozen=True)
class AgentPostInstallObservationConfig:
    vm_name: str
    expected_agent_sha256: str
    expected_agent_version: str
    service: AgentServiceConfig
    runtime: AgentServiceRuntimeConfig

    def validate(self) -> None:
        if not self.vm_name.strip():
            raise ValueError("vm_name is required")
        if len(self.expected_agent_sha256) != 64:
            raise ValueError("expected_agent_sha256 must contain 64 hex characters")
        try:
            int(self.expected_agent_sha256, 16)
        except ValueError as exc:
            raise ValueError("expected_agent_sha256 must be hexadecimal") from exc
        if not self.expected_agent_version.strip():
            raise ValueError("expected_agent_version is required")
        self.service.validate()
        self.runtime.validate()


@dataclass(frozen=True)
class AgentPostInstallObservation:
    service_evidence: dict[str, object]
    health: AgentHealthDocument | None
    health_error: str | None = None

    @property
    def service_ready(self) -> bool:
        return bool(self.service_evidence.get("service_ready", False))

    @property
    def agent_healthy(self) -> bool:
        return self.service_ready and self.health is not None and self.health_error is None

    def to_provision_observation(self) -> ProvisionObservation:
        return ProvisionObservation(
            agent_service_ready=self.service_ready,
            agent_healthy=self.agent_healthy,
        )


class AgentPostInstallObserver:
    """Read-only SCM + application health observation before bootstrap retirement."""

    def __init__(self, config: AgentPostInstallObservationConfig) -> None:
        config.validate()
        self.config = config

    def observe(
        self,
        credential: PowerShellDirectCredential,
    ) -> AgentPostInstallObservation:
        credential.validate()
        service_evidence = probe_agent_service_readiness(
            self.config.vm_name,
            credential,
            self.config.service,
            expected_sha256=self.config.expected_agent_sha256,
            runtime_config=self.config.runtime,
        )
        if not bool(service_evidence.get("service_ready", False)):
            return AgentPostInstallObservation(
                service_evidence=service_evidence,
                health=None,
                health_error="service_not_ready",
            )

        try:
            health = probe_agent_application_health_for_runtime(
                self.config.vm_name,
                credential,
                self.config.runtime,
                expected_agent_version=self.config.expected_agent_version,
            )
        except Exception as exc:
            # Observation must fail closed without copying endpoint content or
            # credential data into durable provisioning state. Keep only the
            # exception class as non-sensitive diagnostic evidence.
            return AgentPostInstallObservation(
                service_evidence=service_evidence,
                health=None,
                health_error=type(exc).__name__,
            )

        return AgentPostInstallObservation(
            service_evidence=service_evidence,
            health=health,
            health_error=None,
        )

    def provision_observation(
        self,
        credential: PowerShellDirectCredential,
    ) -> ProvisionObservation:
        return self.observe(credential).to_provision_observation()
