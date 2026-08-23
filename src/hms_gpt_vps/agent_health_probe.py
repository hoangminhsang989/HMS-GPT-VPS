from __future__ import annotations

from dataclasses import dataclass

from .agent_health_contract import (
    AgentHealthDocument,
    AgentHealthExpectation,
    parse_agent_health,
)
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


@dataclass(frozen=True)
class AgentHealthProbeConfig:
    port: int = 8765
    path: str = "/healthz"
    timeout_seconds: int = 5

    def validate(self) -> None:
        if not (1024 <= self.port <= 65535):
            raise ValueError("agent health port must be between 1024 and 65535")
        if self.path != "/healthz":
            raise ValueError("only the canonical /healthz path is supported")
        if not (1 <= self.timeout_seconds <= 30):
            raise ValueError("health timeout must be between 1 and 30 seconds")

    @property
    def uri(self) -> str:
        self.validate()
        return f"http://127.0.0.1:{self.port}{self.path}"


def build_agent_health_probe_script(config: AgentHealthProbeConfig) -> str:
    """Build a guest script that can contact only the loopback Agent endpoint."""
    config.validate()
    uri = config.uri
    timeout = config.timeout_seconds
    return f"""
$ErrorActionPreference = 'Stop'
$uri = '{uri}'
$response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec {timeout} -MaximumRedirection 0 -ErrorAction Stop
if ($null -eq $response) {{ throw 'HMS Agent health endpoint returned no document' }}
$response
""".strip()


def probe_agent_application_health(
    vm_name: str,
    credential: PowerShellDirectCredential,
    expectation: AgentHealthExpectation,
    *,
    config: AgentHealthProbeConfig | None = None,
) -> AgentHealthDocument:
    """Probe and strictly validate the real Agent application health contract."""
    probe_config = config or AgentHealthProbeConfig()
    payload = run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_health_probe_script(probe_config),
        timeout_seconds=probe_config.timeout_seconds + 15,
    )
    return parse_agent_health(payload, expectation)
