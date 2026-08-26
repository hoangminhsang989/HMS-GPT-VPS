from __future__ import annotations

from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo
import hashlib

import pytest

import hms_gpt_vps.secure_mcp_tunnel_package as module
import hms_gpt_vps.secure_mcp_tunnel_package_io as package_io
import hms_gpt_vps.secure_mcp_tunnel_package_acl as package_acl


SID = "S-1-5-80-1-2-3-4-5"


def file_records(payloads: dict[str, bytes]) -> tuple[module.TunnelRuntimeFileRecord, ...]:
    return tuple(
        module.TunnelRuntimeFileRecord(
            name=name,
            size=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
        )
        for name, payload in sorted(payloads.items())
    )


def exact_payloads() -> dict[str, bytes]:
    return {name: ("payload:" + name).encode() for name in module.EXPECTED_RUNTIME_ARCHIVE_FILES}


def synthetic_zip(payloads: dict[str, bytes]) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, "w", ZIP_DEFLATED) as archive:
        for name, payload in sorted(payloads.items()):
            archive.writestr(name, payload)
    return buffer.getvalue()


def synthetic_manifest(payloads: dict[str, bytes]) -> module.TunnelRuntimePackageManifest:
    return module.TunnelRuntimePackageManifest(files=file_records(payloads))


def test_manifest_is_canonical_and_rejects_duplicate_keys():
    manifest = synthetic_manifest(exact_payloads())
    encoded = manifest.to_json()
    assert module.TunnelRuntimePackageManifest.from_json(encoded) == manifest
    duplicate = encoded.replace("{", '{"schema_version":1,', 1)
    with pytest.raises(module.TunnelRuntimePackageError, match="duplicate"):
        module.TunnelRuntimePackageManifest.from_json(duplicate)


def test_manifest_rejects_boolean_schema_version():
    manifest = module.TunnelRuntimePackageManifest(files=file_records(exact_payloads()), schema_version=True)
    with pytest.raises(module.TunnelRuntimePackageError, match="schema"):
        manifest.validate()


def test_manifest_requires_exact_five_file_upstream_set():
    records = file_records(exact_payloads())
    with pytest.raises(module.TunnelRuntimePackageError, match="count"):
        module.TunnelRuntimePackageManifest(files=records[:-1]).validate()
    bad = module.TunnelRuntimeFileRecord(name="extra.exe", size=1, sha256="0" * 64)
    with pytest.raises(module.TunnelRuntimePackageError, match="unknown"):
        bad.validate()


def test_verified_archive_read_requires_exact_pinned_filename(monkeypatch, tmp_path):
    wrong = tmp_path / "renamed.zip"
    wrong.write_bytes(b"irrelevant")

    class FakePin:
        asset_name = module.OPENAI_TUNNEL_CLIENT_ASSET
        asset_size = len(b"irrelevant")
        sha256 = hashlib.sha256(b"irrelevant").hexdigest()

        def validate(self):
            return None

    monkeypatch.setattr(package_io, "TunnelClientPackagePin", FakePin)
    with pytest.raises(module.TunnelRuntimePackageError, match="filename differs"):
        package_io._read_verified_archive_bytes(wrong)


def test_zip_member_validation_rejects_path_encryption_and_nonregular():
    path_member = ZipInfo("../tunnel-client-runtime.exe")
    path_member.file_size = 1
    with pytest.raises(module.TunnelRuntimePackageError, match="member path"):
        package_io._validate_zip_info(path_member)

    encrypted = ZipInfo(module.OPENAI_TUNNEL_CLIENT_EXECUTABLE)
    encrypted.file_size = 1
    encrypted.flag_bits = 1
    with pytest.raises(module.TunnelRuntimePackageError, match="encrypted"):
        package_io._validate_zip_info(encrypted)

    symlink = ZipInfo(module.OPENAI_TUNNEL_CLIENT_EXECUTABLE)
    symlink.file_size = 1
    symlink.create_system = 3
    symlink.external_attr = (0o120777 << 16)
    with pytest.raises(module.TunnelRuntimePackageError, match="regular file"):
        package_io._validate_zip_info(symlink)


def test_extract_uses_verified_in_memory_bytes_and_exact_members(monkeypatch, tmp_path):
    payloads = exact_payloads()
    raw = synthetic_zip(payloads)
    manifest = synthetic_manifest(payloads)
    archive_path = tmp_path / module.OPENAI_TUNNEL_CLIENT_ASSET
    archive_path.write_bytes(b"placeholder")
    target = tmp_path / "installed"

    monkeypatch.setattr(package_io, "_read_verified_archive_bytes", lambda path: raw)
    monkeypatch.setattr(package_io, "manifest_from_verified_archive_bytes", lambda value: manifest)

    observed = package_io.extract_verified_tunnel_archive(archive_path, target)
    assert observed == manifest
    assert frozenset(path.name for path in target.iterdir()) == module.EXPECTED_RUNTIME_ARCHIVE_FILES
    for name, payload in payloads.items():
        assert (target / name).read_bytes() == payload


def test_extract_never_overwrites_existing_install_target(monkeypatch, tmp_path):
    payloads = exact_payloads()
    raw = synthetic_zip(payloads)
    manifest = synthetic_manifest(payloads)
    archive_path = tmp_path / module.OPENAI_TUNNEL_CLIENT_ASSET
    archive_path.write_bytes(b"placeholder")
    target = tmp_path / "installed"
    target.mkdir()
    monkeypatch.setattr(package_io, "_read_verified_archive_bytes", lambda path: raw)
    monkeypatch.setattr(package_io, "manifest_from_verified_archive_bytes", lambda value: manifest)
    with pytest.raises(FileExistsError):
        package_io.extract_verified_tunnel_archive(archive_path, target)


class FakeHeaders:
    def __init__(self, length: int):
        self.length = length

    def get(self, name: str):
        return str(self.length) if name == "Content-Length" else None


class FakeResponse:
    status = 200

    def __init__(self, raw: bytes):
        self.stream = BytesIO(raw)
        self.headers = FakeHeaders(len(raw))
        self.closed = False

    def read(self, size: int) -> bytes:
        return self.stream.read(size)

    def geturl(self) -> str:
        return "https://release-assets.githubusercontent.com/signed-object"

    def close(self) -> None:
        self.closed = True


def test_acquisition_is_create_only_https_and_digest_pinned(monkeypatch, tmp_path):
    raw = b"verified-small-archive"
    digest = hashlib.sha256(raw).hexdigest()
    target = tmp_path / module.OPENAI_TUNNEL_CLIENT_ASSET
    response = FakeResponse(raw)

    class FakePin:
        asset_name = module.OPENAI_TUNNEL_CLIENT_ASSET
        asset_size = len(raw)
        sha256 = digest

        def validate(self):
            return None

    monkeypatch.setattr(package_io, "OPENAI_TUNNEL_CLIENT_ASSET_SIZE", len(raw))
    monkeypatch.setattr(package_io, "OPENAI_TUNNEL_CLIENT_SHA256", digest)
    monkeypatch.setattr(package_io, "TunnelClientPackagePin", FakePin)
    monkeypatch.setattr(package_io, "_read_verified_archive_bytes", lambda path: raw)

    observed = package_io.acquire_official_tunnel_archive(
        target,
        opener=lambda request, timeout: response,
    )
    assert observed == digest
    assert target.read_bytes() == raw
    assert response.closed is True
    with pytest.raises(FileExistsError):
        package_io.acquire_official_tunnel_archive(
            target,
            opener=lambda request, timeout: FakeResponse(raw),
        )


def test_installed_files_are_rehashed_against_admin_owned_manifest(tmp_path):
    payloads = exact_payloads()
    manifest = synthetic_manifest(payloads)
    install = tmp_path / "installed"
    install.mkdir()
    for name, payload in payloads.items():
        (install / name).write_bytes(payload)
    executable_hash = module._prove_files_against_manifest(install, manifest)
    expected = hashlib.sha256(payloads[module.OPENAI_TUNNEL_CLIENT_EXECUTABLE]).hexdigest()
    assert executable_hash == expected
    (install / module.OPENAI_TUNNEL_CLIENT_EXECUTABLE).write_bytes(b"tampered")
    with pytest.raises(module.TunnelRuntimePackageError, match="differs"):
        module._prove_files_against_manifest(install, manifest)


def test_acl_authority_is_read_execute_for_service_and_exact_entry_set():
    config = module.TunnelRuntimePackageConfig()
    script = package_acl.build_tunnel_package_acl_script(
        config,
        service_sid=SID,
        reconcile=False,
    )
    assert "ReadAndExecute" in script
    assert "FullControl" in script
    assert "$reconcile=$false" in script
    assert module.OPENAI_TUNNEL_CLIENT_EXECUTABLE in script
    assert module.OPENAI_TUNNEL_CLIENT_LICENSE_REPORT in script
    assert module.OPENAI_TUNNEL_CLIENT_SBOM in script
    assert "unexpected entry" in script
    assert "reparse point" in script
