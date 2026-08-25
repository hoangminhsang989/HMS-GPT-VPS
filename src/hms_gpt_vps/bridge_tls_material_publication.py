from __future__ import annotations

import hashlib
import os
from pathlib import Path, PureWindowsPath
import secrets
import ssl
import stat

from .agent_bridge_production_tls import AgentBridgeProductionTlsConfig
from .agent_bridge_tls_deployment import AgentBridgeTlsMaterialConfig, load_agent_bridge_tls_material
from .agent_bridge_tls_storage import ensure_agent_bridge_private_key_storage
from .bridge_service_identity import require_hms_bridge_service_sid
from .bridge_service_provisioning_identity import prove_hms_bridge_provisioning_identity
from .powershell import ps_literal, run_powershell_json
from .qualification_file_authority import path_chain_has_redirect

BRIDGE_TLS_MATERIAL_ROOT = PureWindowsPath(r"C:\ProgramData\HMS-GPT-VPS\Bridge\tls-material")
BRIDGE_TLS_CERTIFICATE_DIR = BRIDGE_TLS_MATERIAL_ROOT / "certificate"
BRIDGE_TLS_PRIVATE_DIR = BRIDGE_TLS_MATERIAL_ROOT / "private"
BRIDGE_TLS_CERTIFICATE_PATH = BRIDGE_TLS_CERTIFICATE_DIR / "agent-bridge.pem"
BRIDGE_TLS_PRIVATE_KEY_PATH = BRIDGE_TLS_PRIVATE_DIR / "agent-bridge-private-key.pem"
_MAX_BYTES = 64 * 1024
_SYSTEM_SID = "S-1-5-18"
_ADMIN_SID = "S-1-5-32-544"


class BridgeTlsMaterialPublicationError(RuntimeError):
    pass


def _same_windows_path(value: Path, expected: PureWindowsPath) -> bool:
    return str(PureWindowsPath(str(value))).casefold() == str(expected).casefold()


def require_fixed_bridge_tls_material_paths(config: AgentBridgeProductionTlsConfig) -> None:
    if not isinstance(config, AgentBridgeProductionTlsConfig):
        raise TypeError("config must be an AgentBridgeProductionTlsConfig")
    checks = (
        (config.material.certificate_path, BRIDGE_TLS_CERTIFICATE_PATH, "certificate"),
        (config.material.private_key_path, BRIDGE_TLS_PRIVATE_KEY_PATH, "private-key"),
        (config.storage.storage_root, BRIDGE_TLS_PRIVATE_DIR, "private-key storage root"),
        (config.storage.private_key_path, BRIDGE_TLS_PRIVATE_KEY_PATH, "storage key"),
    )
    for observed, expected, label in checks:
        if not _same_windows_path(observed, expected):
            raise BridgeTlsMaterialPublicationError(
                f"production TLS {label} path differs from fixed Bridge authority"
            )


def _certificate_der_sha256(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("certificate_pem must be bytes")
    if not data or len(data) > _MAX_BYTES:
        raise BridgeTlsMaterialPublicationError("TLS certificate PEM size is invalid")
    try:
        text = data.decode("ascii")
        if text.count("-----BEGIN CERTIFICATE-----") != 1 or text.count("-----END CERTIFICATE-----") != 1:
            raise ValueError("certificate count")
        der = ssl.PEM_cert_to_DER_cert(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise BridgeTlsMaterialPublicationError("TLS certificate PEM is invalid") from exc
    if not der:
        raise BridgeTlsMaterialPublicationError("TLS certificate DER is empty")
    return hashlib.sha256(der).hexdigest()


def _private_key_sha256(data: bytes) -> str:
    if not isinstance(data, bytes):
        raise TypeError("private_key_pem must be bytes")
    if not data or len(data) > _MAX_BYTES:
        raise BridgeTlsMaterialPublicationError("TLS private-key PEM size is invalid")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise BridgeTlsMaterialPublicationError("TLS private-key PEM must be ASCII") from exc
    if "ENCRYPTED" in text.upper():
        raise BridgeTlsMaterialPublicationError("TLS private key must be deployment-unlocked")
    markers = (
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
    )
    if sum(text.count(marker) for marker in markers) != 1:
        raise BridgeTlsMaterialPublicationError("TLS private-key PEM shape is invalid")
    return hashlib.sha256(data).hexdigest()


def _validate_inputs(config: AgentBridgeProductionTlsConfig, certificate_pem: bytes, private_key_pem: bytes) -> tuple[str, str]:
    config.validate()
    require_fixed_bridge_tls_material_paths(config)
    require_hms_bridge_service_sid(config.storage.bridge_reader_sid)
    cert_der_sha = _certificate_der_sha256(certificate_pem)
    key_sha = _private_key_sha256(private_key_pem)
    if cert_der_sha != config.material.certificate_der_sha256:
        raise BridgeTlsMaterialPublicationError("TLS certificate DER SHA-256 differs from authority")
    if key_sha != config.material.private_key_file_sha256 or key_sha != config.storage.private_key_file_sha256:
        raise BridgeTlsMaterialPublicationError("TLS private-key SHA-256 differs from authority")
    return cert_der_sha, key_sha


def _prepare_script(stage_root: PureWindowsPath, service_sid: str) -> str:
    root, stage, sid = map(ps_literal, (str(BRIDGE_TLS_MATERIAL_ROOT), str(stage_root), service_sid))
    return f"""
$ErrorActionPreference='Stop'
$final=[IO.Path]::GetFullPath({root}); $stage=[IO.Path]::GetFullPath({stage}); $sid={sid}
$parent=[IO.Path]::GetDirectoryName($final)
if ([IO.Path]::GetDirectoryName($stage) -ine $parent) {{ throw 'TLS stage escaped Bridge parent' }}
if (Test-Path -LiteralPath $final) {{ throw 'Bridge TLS material already exists' }}
if (Test-Path -LiteralPath $stage) {{ throw 'Bridge TLS stage already exists' }}
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {{ throw 'Bridge parent missing' }}
$certDir=[IO.Path]::Combine($stage,'certificate'); $keyDir=[IO.Path]::Combine($stage,'private')
$cert=[IO.Path]::Combine($certDir,'agent-bridge.pem'); $key=[IO.Path]::Combine($keyDir,'agent-bridge-private-key.pem')
New-Item Directory $certDir -Force|Out-Null; New-Item Directory $keyDir -Force|Out-Null
$system=[Security.Principal.SecurityIdentifier]::new('{_SYSTEM_SID}'); $admins=[Security.Principal.SecurityIdentifier]::new('{_ADMIN_SID}')
function Protect-Dir($p) {{
 $a=[Security.AccessControl.DirectorySecurity]::new(); $a.SetAccessRuleProtection($true,$false); $a.SetOwner($admins)
 foreach($s in @($system,$admins)) {{ $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)) }}
 Set-Acl -LiteralPath $p -AclObject $a
}}
Protect-Dir $stage; Protect-Dir $certDir; Protect-Dir $keyDir
foreach($p in @($cert,$key)) {{
 $f=[IO.File]::Open($p,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); $f.Dispose()
 $a=[Security.AccessControl.FileSecurity]::new(); $a.SetAccessRuleProtection($true,$false); $a.SetOwner($admins)
 foreach($s in @($system,$admins)) {{ $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($s,[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow)) }}
 Set-Acl -LiteralPath $p -AclObject $a
}}
[pscustomobject]@{{ready=$true;stage_root=$stage;certificate_path=$cert;private_key_path=$key;service_sid=$sid}}
""".strip()


def _write_precreated(path: Path, data: bytes, label: str) -> None:
    if path_chain_has_redirect(path):
        raise BridgeTlsMaterialPublicationError(f"{label} staging path traverses a redirect")
    fd = os.open(path, os.O_WRONLY | getattr(os, "O_BINARY", 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size != 0:
            raise BridgeTlsMaterialPublicationError(f"{label} staging file is not empty regular file")
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data); handle.flush(); os.fsync(handle.fileno())
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or after.st_size != len(data):
            raise BridgeTlsMaterialPublicationError(f"{label} changed during write")
    finally:
        os.close(fd)
    if path_chain_has_redirect(path):
        raise BridgeTlsMaterialPublicationError(f"{label} staging path changed after write")


def _stage_material_config(config: AgentBridgeProductionTlsConfig, cert: Path, key: Path) -> AgentBridgeTlsMaterialConfig:
    return AgentBridgeTlsMaterialConfig(
        network=config.material.network,
        certificate_path=cert,
        private_key_path=key,
        certificate_der_sha256=config.material.certificate_der_sha256,
        private_key_file_sha256=config.material.private_key_file_sha256,
        port=config.material.port,
    )


def _publish_script(stage_root: PureWindowsPath, cert_file_sha: str, key_sha: str, service_sid: str) -> str:
    root, stage, csha, ksha, sid = map(ps_literal, (str(BRIDGE_TLS_MATERIAL_ROOT), str(stage_root), cert_file_sha, key_sha, service_sid))
    return f"""
$ErrorActionPreference='Stop'
$final=[IO.Path]::GetFullPath({root}); $stage=[IO.Path]::GetFullPath({stage}); $certSha={csha}; $keySha={ksha}; $sid={sid}
$cert=[IO.Path]::Combine($stage,'certificate','agent-bridge.pem'); $key=[IO.Path]::Combine($stage,'private','agent-bridge-private-key.pem')
if (Test-Path -LiteralPath $final) {{ throw 'Bridge TLS material already exists' }}
foreach($p in @($stage,$cert,$key)) {{ $i=Get-Item -LiteralPath $p -Force; if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0) {{ throw 'TLS stage contains reparse point' }} }}
if ((Get-FileHash $cert -Algorithm SHA256).Hash.ToLowerInvariant() -ne $certSha) {{ throw 'TLS certificate file hash changed' }}
if ((Get-FileHash $key -Algorithm SHA256).Hash.ToLowerInvariant() -ne $keySha) {{ throw 'TLS private-key hash changed' }}
[IO.Directory]::Move($stage,$final)
$certDir=[IO.Path]::Combine($final,'certificate'); $cert=[IO.Path]::Combine($certDir,'agent-bridge.pem')
$system=[Security.Principal.SecurityIdentifier]::new('{_SYSTEM_SID}'); $admins=[Security.Principal.SecurityIdentifier]::new('{_ADMIN_SID}'); $reader=[Security.Principal.SecurityIdentifier]::new($sid)
function Protect-ReadableDir($p) {{
 $a=[Security.AccessControl.DirectorySecurity]::new(); $a.SetAccessRuleProtection($true,$false); $a.SetOwner($admins)
 foreach($x in @(@($system,[Security.AccessControl.FileSystemRights]::FullControl),@($admins,[Security.AccessControl.FileSystemRights]::FullControl),@($reader,[Security.AccessControl.FileSystemRights]::ReadAndExecute))) {{ $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($x[0],$x[1],[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)) }}
 Set-Acl -LiteralPath $p -AclObject $a
}}
Protect-ReadableDir $final; Protect-ReadableDir $certDir
$a=[Security.AccessControl.FileSecurity]::new(); $a.SetAccessRuleProtection($true,$false); $a.SetOwner($admins)
foreach($x in @(@($system,[Security.AccessControl.FileSystemRights]::FullControl),@($admins,[Security.AccessControl.FileSystemRights]::FullControl),@($reader,[Security.AccessControl.FileSystemRights]::Read))) {{ $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($x[0],$x[1],[Security.AccessControl.AccessControlType]::Allow)) }}
Set-Acl -LiteralPath $cert -AclObject $a
$key=[IO.Path]::Combine($final,'private','agent-bridge-private-key.pem')
[pscustomobject]@{{ready=$true;published=$true;final_root=$final;certificate_path=$cert;private_key_path=$key;certificate_file_sha256=(Get-FileHash $cert -Algorithm SHA256).Hash.ToLowerInvariant();private_key_file_sha256=(Get-FileHash $key -Algorithm SHA256).Hash.ToLowerInvariant();service_sid=$sid}}
""".strip()


def publish_bridge_tls_material_create_only(config: AgentBridgeProductionTlsConfig, certificate_pem: bytes, private_key_pem: bytes) -> dict[str, object]:
    cert_der_sha, key_sha = _validate_inputs(config, certificate_pem, private_key_pem)
    before = prove_hms_bridge_provisioning_identity()
    service_sid = require_hms_bridge_service_sid(before["service_sid"])
    if service_sid != config.storage.bridge_reader_sid:
        raise BridgeTlsMaterialPublicationError("provisioning SID differs from TLS reader authority")

    stage_root = PureWindowsPath(str(BRIDGE_TLS_MATERIAL_ROOT) + ".stage-" + secrets.token_hex(16))
    prepared = run_powershell_json(_prepare_script(stage_root, service_sid), timeout_seconds=60)
    expected = {"ready", "stage_root", "certificate_path", "private_key_path", "service_sid"}
    if frozenset(prepared) != expected or prepared.get("ready") is not True or prepared.get("service_sid") != service_sid:
        raise BridgeTlsMaterialPublicationError("TLS staging evidence is invalid")
    stage_cert = stage_root / "certificate" / "agent-bridge.pem"
    stage_key = stage_root / "private" / "agent-bridge-private-key.pem"
    for key, wanted in (("stage_root", stage_root), ("certificate_path", stage_cert), ("private_key_path", stage_key)):
        if str(prepared.get(key, "")).casefold() != str(wanted).casefold():
            raise BridgeTlsMaterialPublicationError(f"TLS staging {key} differs from authority")

    cert_path, key_path = Path(str(stage_cert)), Path(str(stage_key))
    _write_precreated(cert_path, certificate_pem, "TLS certificate")
    _write_precreated(key_path, private_key_pem, "TLS private key")
    staged = load_agent_bridge_tls_material(_stage_material_config(config, cert_path, key_path)); staged.validate()

    middle = prove_hms_bridge_provisioning_identity()
    if middle["service_sid"] != service_sid:
        raise BridgeTlsMaterialPublicationError("HMSBridge SID changed before TLS publication")
    cert_file_sha = hashlib.sha256(certificate_pem).hexdigest()
    published = run_powershell_json(_publish_script(stage_root, cert_file_sha, key_sha, service_sid), timeout_seconds=60)
    expected = {"ready", "published", "final_root", "certificate_path", "private_key_path", "certificate_file_sha256", "private_key_file_sha256", "service_sid"}
    if frozenset(published) != expected or published.get("ready") is not True or published.get("published") is not True:
        raise BridgeTlsMaterialPublicationError("TLS publication evidence is invalid")
    exact = (
        ("final_root", BRIDGE_TLS_MATERIAL_ROOT),
        ("certificate_path", BRIDGE_TLS_CERTIFICATE_PATH),
        ("private_key_path", BRIDGE_TLS_PRIVATE_KEY_PATH),
    )
    for key, wanted in exact:
        if str(published.get(key, "")).casefold() != str(wanted).casefold():
            raise BridgeTlsMaterialPublicationError(f"published TLS {key} differs from authority")
    if published.get("service_sid") != service_sid or published.get("certificate_file_sha256") != cert_file_sha or published.get("private_key_file_sha256") != key_sha:
        raise BridgeTlsMaterialPublicationError("published TLS identity differs from authority")

    first = ensure_agent_bridge_private_key_storage(config.storage)
    second = ensure_agent_bridge_private_key_storage(config.storage)
    if first.get("ready") is not True or second.get("ready") is not True or second.get("changed") is not False:
        raise BridgeTlsMaterialPublicationError("TLS private-key ACL did not converge and re-prove exact")
    final_material = load_agent_bridge_tls_material(config.material); final_material.validate()
    after = prove_hms_bridge_provisioning_identity()
    if after["service_sid"] != service_sid:
        raise BridgeTlsMaterialPublicationError("HMSBridge SID changed across TLS publication")

    return {
        "ready": True,
        "published": True,
        "service_sid": service_sid,
        "service_state": after["service_state"],
        "service_start_mode": after["service_start_mode"],
        "certificate_path": str(BRIDGE_TLS_CERTIFICATE_PATH),
        "private_key_path": str(BRIDGE_TLS_PRIVATE_KEY_PATH),
        "certificate_der_sha256": cert_der_sha,
        "certificate_file_sha256": cert_file_sha,
        "private_key_file_sha256": key_sha,
        "private_key_acl_exact": True,
        "runtime_listener_started": False,
        "pairing_ready": False,
    }
