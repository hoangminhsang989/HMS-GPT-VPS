from __future__ import annotations

import base64
from dataclasses import dataclass
import json
from typing import Mapping

from .agent_health_contract import (
    DEFAULT_REQUIRED_CAPABILITIES,
    AgentHealthDocument,
    AgentHealthExpectation,
    parse_agent_health,
)
from .agent_service_runtime_config import AgentServiceRuntimeConfig
from .powershell_direct import PowerShellDirectCredential, run_vm_powershell_json


_MAX_HEALTH_BODY_BYTES = 32 * 1024


class AgentHealthProbeError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentHealthProbeConfig:
    port: int = 8765
    path: str = "/healthz"
    timeout_seconds: int = 5
    max_body_bytes: int = _MAX_HEALTH_BODY_BYTES

    def validate(self) -> None:
        if not isinstance(self.port, int) or isinstance(self.port, bool):
            raise ValueError("agent health port must be an integer")
        if not (1024 <= self.port <= 65535):
            raise ValueError("agent health port must be between 1024 and 65535")
        if self.path != "/healthz":
            raise ValueError("only the canonical /healthz path is supported")
        if not isinstance(self.timeout_seconds, int) or isinstance(
            self.timeout_seconds, bool
        ):
            raise ValueError("health timeout must be an integer")
        if not (1 <= self.timeout_seconds <= 30):
            raise ValueError("health timeout must be between 1 and 30 seconds")
        if not isinstance(self.max_body_bytes, int) or isinstance(
            self.max_body_bytes, bool
        ):
            raise ValueError("health body limit must be an integer")
        if not (1024 <= self.max_body_bytes <= _MAX_HEALTH_BODY_BYTES):
            raise ValueError(
                f"health body limit must be between 1024 and {_MAX_HEALTH_BODY_BYTES} bytes"
            )

    @property
    def uri(self) -> str:
        self.validate()
        return f"http://127.0.0.1:{self.port}{self.path}"


def build_agent_health_probe_script(config: AgentHealthProbeConfig) -> str:
    """Build a bounded, no-redirect/no-proxy guest loopback health request."""
    config.validate()
    uri = config.uri
    timeout_ms = config.timeout_seconds * 1000
    max_body = config.max_body_bytes
    return f"""
$ErrorActionPreference = 'Stop'
$uri = '{uri}'
$maxBodyBytes = {max_body}
$request = [System.Net.HttpWebRequest]::Create($uri)
$request.Method = 'GET'
$request.AllowAutoRedirect = $false
$request.Proxy = $null
$request.KeepAlive = $false
$request.Timeout = {timeout_ms}
$request.ReadWriteTimeout = {timeout_ms}
$request.UserAgent = 'HMS-Provisioning-Health-Probe/1'
$response = $null
$stream = $null
$memory = $null
try {{
  $response = [System.Net.HttpWebResponse]$request.GetResponse()
  $statusCode = [int]$response.StatusCode
  if ($statusCode -ne 200) {{ throw "HMS Agent health HTTP status was $statusCode" }}
  $contentType = [string]$response.ContentType
  if ($contentType -notmatch '^(?i:application/json)(?:\\s*;|$)') {{
    throw 'HMS Agent health Content-Type is not application/json'
  }}
  if ($response.ContentLength -gt $maxBodyBytes) {{
    throw 'HMS Agent health body exceeds the configured limit'
  }}

  $stream = $response.GetResponseStream()
  if ($null -eq $stream) {{ throw 'HMS Agent health response stream is missing' }}
  $memory = [System.IO.MemoryStream]::new()
  $buffer = New-Object byte[] 4096
  while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {{
    if (($memory.Length + $read) -gt $maxBodyBytes) {{
      throw 'HMS Agent health body exceeds the configured limit'
    }}
    $memory.Write($buffer, 0, $read)
  }}
  $body = $memory.ToArray()
  if ($body.Length -eq 0) {{ throw 'HMS Agent health endpoint returned an empty body' }}

  [pscustomobject]@{{
    uri = $uri
    status_code = $statusCode
    content_type = $contentType
    body_bytes = [int]$body.Length
    body_b64 = [Convert]::ToBase64String($body)
    redirects_allowed = $false
    proxy_enabled = $false
  }}
}} finally {{
  if ($null -ne $memory) {{ $memory.Dispose() }}
  if ($null -ne $stream) {{ $stream.Dispose() }}
  if ($null -ne $response) {{ $response.Dispose() }}
}}
""".strip()


def _require_probe_text(result: Mapping[str, object], name: str) -> str:
    value = result.get(name)
    if not isinstance(value, str) or not value.strip():
        raise AgentHealthProbeError(f"health probe {name} must be a non-empty string")
    return value


def _decode_probe_payload(
    result: Mapping[str, object],
    config: AgentHealthProbeConfig,
) -> Mapping[str, object]:
    status = result.get("status_code")
    if not isinstance(status, int) or isinstance(status, bool) or status != 200:
        raise AgentHealthProbeError("health probe did not prove HTTP 200")

    uri = _require_probe_text(result, "uri")
    if uri != config.uri:
        raise AgentHealthProbeError("health probe URI does not match loopback target")

    content_type = _require_probe_text(result, "content_type")
    media_type = content_type.split(";", 1)[0].strip().casefold()
    if media_type != "application/json":
        raise AgentHealthProbeError("health probe Content-Type is not application/json")

    if result.get("redirects_allowed") is not False:
        raise AgentHealthProbeError("health probe did not prove redirects were disabled")
    if result.get("proxy_enabled") is not False:
        raise AgentHealthProbeError("health probe did not prove proxy bypass")

    body_bytes = result.get("body_bytes")
    if (
        not isinstance(body_bytes, int)
        or isinstance(body_bytes, bool)
        or not 1 <= body_bytes <= config.max_body_bytes
    ):
        raise AgentHealthProbeError("health probe body length is outside supported bounds")

    encoded = _require_probe_text(result, "body_b64")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise AgentHealthProbeError("health probe body is not valid base64") from exc
    if len(raw) != body_bytes:
        raise AgentHealthProbeError("health probe body length does not match evidence")
    if len(raw) > config.max_body_bytes:
        raise AgentHealthProbeError("health probe body exceeds supported bounds")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AgentHealthProbeError("health probe body is not valid UTF-8") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise AgentHealthProbeError("health probe body is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise AgentHealthProbeError("health probe JSON body must be an object")
    return payload


def validate_agent_application_health_evidence(
    result: Mapping[str, object],
    expectation: AgentHealthExpectation,
    *,
    expected_agent_version: str,
    config: AgentHealthProbeConfig,
) -> AgentHealthDocument:
    if not isinstance(expected_agent_version, str) or not expected_agent_version.strip():
        raise ValueError("expected_agent_version is required")
    config.validate()
    payload = _decode_probe_payload(result, config)
    document = parse_agent_health(payload, expectation)
    if document.agent_version != expected_agent_version:
        raise AgentHealthProbeError("agent health version does not match approved package")
    if document.capability_set() != DEFAULT_REQUIRED_CAPABILITIES:
        raise AgentHealthProbeError(
            "agent health capabilities do not match the canonical capability set"
        )
    return document


def probe_agent_application_health(
    vm_name: str,
    credential: PowerShellDirectCredential,
    expectation: AgentHealthExpectation,
    *,
    expected_agent_version: str,
    config: AgentHealthProbeConfig | None = None,
) -> AgentHealthDocument:
    """Probe and strictly validate the real Agent application health contract."""
    probe_config = config or AgentHealthProbeConfig()
    probe_config.validate()
    result = run_vm_powershell_json(
        vm_name,
        credential,
        build_agent_health_probe_script(probe_config),
        timeout_seconds=probe_config.timeout_seconds + 15,
    )
    return validate_agent_application_health_evidence(
        result,
        expectation,
        expected_agent_version=expected_agent_version,
        config=probe_config,
    )


def probe_agent_application_health_for_runtime(
    vm_name: str,
    credential: PowerShellDirectCredential,
    runtime_config: AgentServiceRuntimeConfig,
    *,
    expected_agent_version: str,
    timeout_seconds: int = 5,
) -> AgentHealthDocument:
    """Probe the exact health endpoint described by protected service config."""
    runtime_config.validate()
    probe_config = AgentHealthProbeConfig(
        port=runtime_config.health_port,
        timeout_seconds=timeout_seconds,
    )
    expectation = AgentHealthExpectation(
        instance_id=runtime_config.instance_id,
        workspace_root=runtime_config.workspace_root,
        required_capabilities=DEFAULT_REQUIRED_CAPABILITIES,
    )
    return probe_agent_application_health(
        vm_name,
        credential,
        expectation,
        expected_agent_version=expected_agent_version,
        config=probe_config,
    )
