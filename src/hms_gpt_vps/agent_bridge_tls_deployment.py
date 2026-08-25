from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import ssl
import stat
from urllib.parse import urlsplit
import uuid

from .agent_bridge_http_boundary import AgentBridgeHttpBoundary
from .agent_bridge_tls_server import AgentBridgeTlsServer, AgentBridgeTlsServerConfig
from .hyperv_network import HyperVNetworkConfig
from .powershell import ps_literal
from .powershell_direct import (
    PowerShellDirectCredential,
    run_vm_powershell_json_by_id,
)
from .qualification_file_authority import (
    lexical_absolute,
    path_chain_has_redirect,
)


_DEFAULT_AGENT_TLS_PORT = 9443
_MAX_TLS_CERTIFICATE_BYTES = 64 * 1024
_MAX_TLS_PRIVATE_KEY_BYTES = 64 * 1024
_MAX_TRUST_ROOT_DER_BYTES = 8 * 1024
_HEX_SHA256_LENGTH = 64
_ALLOWED_TLS_PROTOCOL_NAMES = frozenset({"Tls12", "Tls13"})


class AgentBridgeTlsDeploymentError(RuntimeError):
    pass


def _require_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _HEX_SHA256_LENGTH
        or value != value.lower()
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise AgentBridgeTlsDeploymentError(
            f"{name} must be canonical lowercase SHA-256 hex"
        )
    return value


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _assert_same_regular_file(
    path: Path,
    opened_stat: os.stat_result,
    *,
    label: str,
) -> None:
    if path_chain_has_redirect(path):
        raise AgentBridgeTlsDeploymentError(
            f"{label} path traverses a link or reparse point"
        )
    try:
        current = path.stat()
    except FileNotFoundError as exc:
        raise AgentBridgeTlsDeploymentError(f"{label} disappeared") from exc
    if (
        not path.is_file()
        or not stat.S_ISREG(current.st_mode)
        or not _same_file_identity(opened_stat, current)
    ):
        raise AgentBridgeTlsDeploymentError(
            f"{label} authority changed during access"
        )


def _read_pinned_regular_file(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[Path, bytes, os.stat_result]:
    if not isinstance(path, Path):
        raise TypeError(f"{label} path must be a pathlib.Path")
    authority = lexical_absolute(path)
    if path_chain_has_redirect(authority):
        raise AgentBridgeTlsDeploymentError(
            f"{label} path traverses a link or reparse point"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(authority, flags)
    except FileNotFoundError as exc:
        raise AgentBridgeTlsDeploymentError(f"{label} is missing") from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise AgentBridgeTlsDeploymentError(
                f"{label} must be a regular file"
            )
        if opened.st_size <= 0 or opened.st_size > max_bytes:
            raise AgentBridgeTlsDeploymentError(
                f"{label} size is outside supported bounds"
            )
        _assert_same_regular_file(authority, opened, label=label)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
            after = os.fstat(handle.fileno())
        if not _same_file_identity(opened, after):
            raise AgentBridgeTlsDeploymentError(
                f"{label} opened-file identity changed"
            )
        if len(data) != opened.st_size or len(data) > max_bytes:
            raise AgentBridgeTlsDeploymentError(
                f"{label} changed during read"
            )
        _assert_same_regular_file(authority, opened, label=label)
        return authority, data, opened
    finally:
        os.close(fd)


def _certificate_der_from_pem(data: bytes) -> bytes:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge certificate PEM must be ASCII"
        ) from exc
    if text.count("-----BEGIN CERTIFICATE-----") != 1 or text.count(
        "-----END CERTIFICATE-----"
    ) != 1:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge certificate file must contain exactly one certificate"
        )
    try:
        der = ssl.PEM_cert_to_DER_cert(text)
    except ValueError as exc:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge certificate PEM is invalid"
        ) from exc
    if not der:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge certificate DER is empty"
        )
    return der


def _require_unencrypted_private_key(data: bytes) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge private key PEM must be ASCII"
        ) from exc
    if "ENCRYPTED" in text.upper():
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge private key must be deployment-unlocked before service start"
        )
    begin_markers = (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    )
    if sum(text.count(marker) for marker in begin_markers) != 1:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge private key file must contain exactly one supported key"
        )


@dataclass(frozen=True)
class AgentBridgeTlsMaterialConfig:
    network: HyperVNetworkConfig
    certificate_path: Path
    private_key_path: Path
    certificate_der_sha256: str
    private_key_file_sha256: str
    port: int = _DEFAULT_AGENT_TLS_PORT

    def validate(self) -> None:
        AgentBridgeTlsServerConfig(
            network=self.network,
            port=self.port,
        ).validate()
        if not isinstance(self.certificate_path, Path):
            raise TypeError("certificate_path must be a pathlib.Path")
        if not isinstance(self.private_key_path, Path):
            raise TypeError("private_key_path must be a pathlib.Path")
        certificate_path = lexical_absolute(self.certificate_path)
        key_path = lexical_absolute(self.private_key_path)
        if certificate_path == key_path:
            raise AgentBridgeTlsDeploymentError(
                "Agent Bridge certificate and private key paths must differ"
            )
        _require_sha256(
            self.certificate_der_sha256,
            "certificate_der_sha256",
        )
        _require_sha256(
            self.private_key_file_sha256,
            "private_key_file_sha256",
        )

    @property
    def bridge_origin(self) -> str:
        self.validate()
        return f"https://{self.network.gateway}:{self.port}"


@dataclass(frozen=True)
class LoadedAgentBridgeTlsMaterial:
    config: AgentBridgeTlsMaterialConfig
    certificate_der_sha256: str
    private_key_file_sha256: str
    ssl_context: ssl.SSLContext = field(repr=False)

    def validate(self) -> None:
        self.config.validate()
        if self.certificate_der_sha256 != self.config.certificate_der_sha256:
            raise AgentBridgeTlsDeploymentError(
                "loaded Agent Bridge certificate identity changed"
            )
        if self.private_key_file_sha256 != self.config.private_key_file_sha256:
            raise AgentBridgeTlsDeploymentError(
                "loaded Agent Bridge private key identity changed"
            )
        if self.ssl_context.protocol != ssl.PROTOCOL_TLS_SERVER:
            raise AgentBridgeTlsDeploymentError(
                "loaded Agent Bridge TLS context is not a server context"
            )
        if self.ssl_context.minimum_version < ssl.TLSVersion.TLSv1_2:
            raise AgentBridgeTlsDeploymentError(
                "loaded Agent Bridge TLS context permits obsolete TLS"
            )


def load_agent_bridge_tls_material(
    config: AgentBridgeTlsMaterialConfig,
) -> LoadedAgentBridgeTlsMaterial:
    """Load one deployment-supplied PEM pair into a pinned TLS server context.

    The function never creates certificates or keys. The certificate identity is
    pinned by DER SHA-256 and the private-key file by exact file SHA-256. The
    paths and opened file identities are checked before and after
    ``SSLContext.load_cert_chain`` so a raced replacement cannot produce a
    publishable context.
    """

    if not isinstance(config, AgentBridgeTlsMaterialConfig):
        raise TypeError("config must be an AgentBridgeTlsMaterialConfig")
    config.validate()

    cert_path, cert_bytes, cert_stat = _read_pinned_regular_file(
        config.certificate_path,
        label="Agent Bridge certificate",
        max_bytes=_MAX_TLS_CERTIFICATE_BYTES,
    )
    key_path, key_bytes, key_stat = _read_pinned_regular_file(
        config.private_key_path,
        label="Agent Bridge private key",
        max_bytes=_MAX_TLS_PRIVATE_KEY_BYTES,
    )
    certificate_der = _certificate_der_from_pem(cert_bytes)
    _require_unencrypted_private_key(key_bytes)

    certificate_der_sha256 = hashlib.sha256(certificate_der).hexdigest()
    private_key_file_sha256 = hashlib.sha256(key_bytes).hexdigest()
    if certificate_der_sha256 != config.certificate_der_sha256:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge certificate SHA-256 does not match deployment authority"
        )
    if private_key_file_sha256 != config.private_key_file_sha256:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge private key SHA-256 does not match deployment authority"
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    try:
        context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(key_path),
        )
    except (OSError, ssl.SSLError) as exc:
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge certificate/private-key pair could not be loaded"
        ) from exc

    _assert_same_regular_file(
        cert_path,
        cert_stat,
        label="Agent Bridge certificate",
    )
    _assert_same_regular_file(
        key_path,
        key_stat,
        label="Agent Bridge private key",
    )
    _, cert_after, cert_after_stat = _read_pinned_regular_file(
        cert_path,
        label="Agent Bridge certificate",
        max_bytes=_MAX_TLS_CERTIFICATE_BYTES,
    )
    _, key_after, key_after_stat = _read_pinned_regular_file(
        key_path,
        label="Agent Bridge private key",
        max_bytes=_MAX_TLS_PRIVATE_KEY_BYTES,
    )
    if (
        not _same_file_identity(cert_stat, cert_after_stat)
        or cert_after != cert_bytes
        or not _same_file_identity(key_stat, key_after_stat)
        or key_after != key_bytes
    ):
        raise AgentBridgeTlsDeploymentError(
            "Agent Bridge TLS material changed while loading"
        )

    loaded = LoadedAgentBridgeTlsMaterial(
        config=config,
        certificate_der_sha256=certificate_der_sha256,
        private_key_file_sha256=private_key_file_sha256,
        ssl_context=context,
    )
    loaded.validate()
    return loaded


def build_agent_bridge_tls_server(
    boundary: AgentBridgeHttpBoundary,
    material: LoadedAgentBridgeTlsMaterial,
) -> AgentBridgeTlsServer:
    """Bind loaded deployment material to the exact managed TLS listener config."""

    if not isinstance(boundary, AgentBridgeHttpBoundary):
        raise TypeError("boundary must be an AgentBridgeHttpBoundary")
    if not isinstance(material, LoadedAgentBridgeTlsMaterial):
        raise TypeError("material must be LoadedAgentBridgeTlsMaterial")
    material.validate()
    return AgentBridgeTlsServer(
        boundary,
        AgentBridgeTlsServerConfig(
            network=material.config.network,
            port=material.config.port,
        ),
        material.ssl_context,
    )


def _trust_root_der(
    certificate_pem: bytes,
    *,
    expected_der_sha256: str,
) -> bytes:
    _require_sha256(expected_der_sha256, "trust_root_der_sha256")
    if not isinstance(certificate_pem, bytes):
        raise TypeError("trust root certificate must be bytes")
    if not certificate_pem or len(certificate_pem) > _MAX_TRUST_ROOT_DER_BYTES:
        raise AgentBridgeTlsDeploymentError(
            "trust root certificate size is outside supported bounds"
        )
    der = _certificate_der_from_pem(certificate_pem)
    if len(der) > _MAX_TRUST_ROOT_DER_BYTES:
        raise AgentBridgeTlsDeploymentError(
            "trust root certificate DER is too large"
        )
    if hashlib.sha256(der).hexdigest() != expected_der_sha256:
        raise AgentBridgeTlsDeploymentError(
            "trust root SHA-256 does not match deployment authority"
        )
    return der


def _normalize_vm_id(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentBridgeTlsDeploymentError("vm_id is required")
    try:
        return str(uuid.UUID(value.strip())).lower()
    except (ValueError, AttributeError) as exc:
        raise AgentBridgeTlsDeploymentError(
            "vm_id must be a valid GUID"
        ) from exc


@dataclass(frozen=True)
class ManagedGuestBridgeTlsConfig:
    network: HyperVNetworkConfig
    vm_id: str
    vm_name: str
    bridge_origin: str
    server_certificate_der_sha256: str
    trust_root_der_sha256: str
    port: int = _DEFAULT_AGENT_TLS_PORT

    def validate(self) -> None:
        AgentBridgeTlsServerConfig(
            network=self.network,
            port=self.port,
        ).validate()
        _normalize_vm_id(self.vm_id)
        if (
            not isinstance(self.vm_name, str)
            or not self.vm_name.strip()
            or self.vm_name != self.vm_name.strip()
        ):
            raise AgentBridgeTlsDeploymentError("vm_name is invalid")
        _require_sha256(
            self.server_certificate_der_sha256,
            "server_certificate_der_sha256",
        )
        _require_sha256(
            self.trust_root_der_sha256,
            "trust_root_der_sha256",
        )
        if not isinstance(self.bridge_origin, str):
            raise AgentBridgeTlsDeploymentError("bridge_origin is invalid")
        parsed = urlsplit(self.bridge_origin)
        if (
            parsed.scheme != "https"
            or parsed.hostname != self.network.gateway
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise AgentBridgeTlsDeploymentError(
                "bridge_origin must be the exact managed private TLS origin"
            )
        try:
            observed_port = parsed.port
        except ValueError as exc:
            raise AgentBridgeTlsDeploymentError(
                "bridge_origin contains an invalid port"
            ) from exc
        if observed_port != self.port:
            raise AgentBridgeTlsDeploymentError(
                "bridge_origin port does not match Agent Bridge TLS port"
            )
        if self.bridge_origin != f"https://{self.network.gateway}:{self.port}":
            raise AgentBridgeTlsDeploymentError(
                "bridge_origin must use canonical managed private IPv4 text"
            )


_GUEST_TRUST_ROOT_SCRIPT = r"""
param([string]$payloadB64)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($payloadB64)) {
  throw 'Agent Bridge trust-root payload missing'
}
$raw = [Convert]::FromBase64String($payloadB64)
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$raw)
if ($cert.HasPrivateKey) {
  throw 'Agent Bridge trust root payload must not contain a private key'
}
if ($cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow) {
  throw 'Agent Bridge trust root is not valid yet'
}
if ($cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow) {
  throw 'Agent Bridge trust root is expired'
}
$basicRaw = @(
  $cert.Extensions |
    Where-Object { $_.Oid.Value -eq '2.5.29.19' }
)
if ($basicRaw.Count -ne 1) {
  throw 'Agent Bridge trust root must have exactly one Basic Constraints extension'
}
$basic = [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new(
  $basicRaw[0],
  [bool]$basicRaw[0].Critical
)
if (-not $basic.CertificateAuthority) {
  throw 'Agent Bridge trust root is not a CA certificate'
}
if ($cert.Subject -ne $cert.Issuer) {
  throw 'Agent Bridge trust root must be a root CA certificate'
}
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
  $sha256 = ([BitConverter]::ToString($sha.ComputeHash($cert.RawData))).Replace('-', '').ToLowerInvariant()
} finally {
  $sha.Dispose()
}
$thumbprint = $cert.Thumbprint.ToUpperInvariant()
$subject = [string]$cert.Subject
$issuer = [string]$cert.Issuer
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$changed = $false
try {
  $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $sameSubject = @($store.Certificates | Where-Object { $_.Subject -eq $cert.Subject })
  $conflicts = @($sameSubject | Where-Object { $_.Thumbprint -ne $thumbprint })
  if ($conflicts.Count -ne 0) {
    throw 'A different LocalMachine root already uses the Agent Bridge trust-root subject'
  }
  $matches = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint })
  if ($matches.Count -gt 1) {
    throw 'Agent Bridge trust root is duplicated in LocalMachine Root'
  }
  if ($matches.Count -eq 0) {
    $store.Add($cert)
    $changed = $true
  }
  $matches = @($store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint })
  if ($matches.Count -ne 1) {
    throw 'Agent Bridge trust root publication did not converge exactly'
  }
} finally {
  $store.Close()
  $cert.Dispose()
}
[pscustomobject]@{
  changed = [bool]$changed
  present = $true
  sha256 = $sha256
  thumbprint = $thumbprint
  subject = $subject
  issuer = $issuer
  store = 'LocalMachine\Root'
  certificate_authority = $true
}
""".strip()


def install_managed_guest_bridge_trust_root_by_id(
    config: ManagedGuestBridgeTlsConfig,
    credential: PowerShellDirectCredential,
    trust_root_certificate_pem: bytes,
    *,
    timeout_seconds: int = 60,
) -> dict[str, object]:
    """Install exactly one deployment-supplied root CA into the managed guest.

    The certificate is supplied as the PowerShell Direct payload, never generated
    by HMS and never embedded in the command line. The function only adds the
    exact pinned root; it never removes or rewrites another trust anchor.
    """

    if not isinstance(config, ManagedGuestBridgeTlsConfig):
        raise TypeError("config must be a ManagedGuestBridgeTlsConfig")
    config.validate()
    credential.validate()
    der = _trust_root_der(
        trust_root_certificate_pem,
        expected_der_sha256=config.trust_root_der_sha256,
    )
    result = run_vm_powershell_json_by_id(
        _normalize_vm_id(config.vm_id),
        config.vm_name,
        credential,
        _GUEST_TRUST_ROOT_SCRIPT,
        timeout_seconds=timeout_seconds,
        secret_payload=der,
    )
    expected_keys = frozenset(
        {
            "changed",
            "present",
            "sha256",
            "thumbprint",
            "subject",
            "issuer",
            "store",
            "certificate_authority",
        }
    )
    if frozenset(result) != expected_keys:
        raise AgentBridgeTlsDeploymentError(
            "managed guest trust-root evidence schema is invalid"
        )
    if result.get("present") is not True:
        raise AgentBridgeTlsDeploymentError(
            "managed guest trust root is not present"
        )
    if result.get("sha256") != config.trust_root_der_sha256:
        raise AgentBridgeTlsDeploymentError(
            "managed guest trust-root identity does not match deployment authority"
        )
    if result.get("store") != r"LocalMachine\Root":
        raise AgentBridgeTlsDeploymentError(
            "managed guest trust root was published to the wrong certificate store"
        )
    if result.get("certificate_authority") is not True:
        raise AgentBridgeTlsDeploymentError(
            "managed guest trust root is not a CA certificate"
        )
    if not isinstance(result.get("changed"), bool):
        raise AgentBridgeTlsDeploymentError(
            "managed guest trust-root changed evidence is invalid"
        )
    for key in ("thumbprint", "subject", "issuer"):
        value = result.get(key)
        if not isinstance(value, str) or not value:
            raise AgentBridgeTlsDeploymentError(
                f"managed guest trust-root evidence is invalid: {key}"
            )
    return dict(result)


def build_managed_guest_bridge_tls_probe_script(
    config: ManagedGuestBridgeTlsConfig,
) -> str:
    config.validate()
    gateway = ps_literal(config.network.gateway)
    target_host = ps_literal(config.network.gateway)
    return f"""
$ErrorActionPreference = 'Stop'
$gateway = {gateway}
$targetHost = {target_host}
$port = [int]{config.port}
$client = New-Object System.Net.Sockets.TcpClient
try {{
  $client.ReceiveTimeout = 10000
  $client.SendTimeout = 10000
  $client.Connect($gateway, $port)
  $localEndpoint = [System.Net.IPEndPoint]$client.Client.LocalEndPoint
  $remoteEndpoint = [System.Net.IPEndPoint]$client.Client.RemoteEndPoint
  $stream = $client.GetStream()
  $ssl = New-Object System.Net.Security.SslStream($stream, $false)
  try {{
    $ssl.AuthenticateAsClient($targetHost)
    if (-not $ssl.IsAuthenticated -or -not $ssl.IsEncrypted -or -not $ssl.IsSigned) {{
      throw 'Agent Bridge TLS session is not fully authenticated'
    }}
    if ($null -eq $ssl.RemoteCertificate) {{
      throw 'Agent Bridge TLS remote certificate missing'
    }}
    $remoteCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $ssl.RemoteCertificate
    try {{
      $sha = [System.Security.Cryptography.SHA256]::Create()
      try {{
        $certSha256 = ([BitConverter]::ToString($sha.ComputeHash($remoteCert.RawData))).Replace('-', '').ToLowerInvariant()
      }} finally {{
        $sha.Dispose()
      }}
      [pscustomobject]@{{
        tcp_connected = $true
        tls_authenticated = $true
        tls_encrypted = $true
        tls_signed = $true
        local_ip = [string]$localEndpoint.Address
        remote_ip = [string]$remoteEndpoint.Address
        remote_port = [int]$remoteEndpoint.Port
        target_host = $targetHost
        tls_protocol = [string]$ssl.SslProtocol
        server_certificate_sha256 = $certSha256
        server_certificate_subject = [string]$remoteCert.Subject
        server_certificate_issuer = [string]$remoteCert.Issuer
      }}
    }} finally {{
      $remoteCert.Dispose()
    }}
  }} finally {{
    $ssl.Dispose()
  }}
}} finally {{
  $client.Dispose()
}}
""".strip()


def probe_managed_guest_bridge_tls_by_id(
    config: ManagedGuestBridgeTlsConfig,
    credential: PowerShellDirectCredential,
    *,
    timeout_seconds: int = 45,
) -> dict[str, object]:
    """Prove live guest-to-host TCP + trusted TLS over the managed Hyper-V NIC."""

    if not isinstance(config, ManagedGuestBridgeTlsConfig):
        raise TypeError("config must be a ManagedGuestBridgeTlsConfig")
    config.validate()
    credential.validate()
    result = run_vm_powershell_json_by_id(
        _normalize_vm_id(config.vm_id),
        config.vm_name,
        credential,
        build_managed_guest_bridge_tls_probe_script(config),
        timeout_seconds=timeout_seconds,
    )
    expected_keys = frozenset(
        {
            "tcp_connected",
            "tls_authenticated",
            "tls_encrypted",
            "tls_signed",
            "local_ip",
            "remote_ip",
            "remote_port",
            "target_host",
            "tls_protocol",
            "server_certificate_sha256",
            "server_certificate_subject",
            "server_certificate_issuer",
        }
    )
    if frozenset(result) != expected_keys:
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS qualification evidence schema is invalid"
        )
    for key in (
        "tcp_connected",
        "tls_authenticated",
        "tls_encrypted",
        "tls_signed",
    ):
        if result.get(key) is not True:
            raise AgentBridgeTlsDeploymentError(
                f"managed guest TLS qualification did not prove: {key}"
            )
    if result.get("local_ip") != config.network.guest_ipv4:
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS connection did not originate from the managed guest IPv4"
        )
    if result.get("remote_ip") != config.network.gateway:
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS connection reached the wrong host IPv4"
        )
    if result.get("remote_port") != config.port:
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS connection reached the wrong port"
        )
    if result.get("target_host") != config.network.gateway:
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS hostname verification used the wrong target"
        )
    if result.get("tls_protocol") not in _ALLOWED_TLS_PROTOCOL_NAMES:
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS negotiated an unsupported protocol"
        )
    if (
        result.get("server_certificate_sha256")
        != config.server_certificate_der_sha256
    ):
        raise AgentBridgeTlsDeploymentError(
            "managed guest TLS server certificate does not match deployment authority"
        )
    for key in ("server_certificate_subject", "server_certificate_issuer"):
        value = result.get(key)
        if not isinstance(value, str) or not value:
            raise AgentBridgeTlsDeploymentError(
                f"managed guest TLS certificate evidence is invalid: {key}"
            )
    evidence = dict(result)
    evidence["vm_id"] = _normalize_vm_id(config.vm_id)
    evidence["bridge_origin"] = config.bridge_origin
    evidence["live_managed_guest_tls_proven"] = True
    return evidence
