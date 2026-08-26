from pathlib import Path

import pytest

import hms_gpt_vps.secure_mcp_tunnel as module
from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig


SID = "S-1-5-80-1-2-3-4-5"
TUNNEL_ID = "tunnel_" + "a" * 32
API_KEY = "restricted-runtime-key-test-value"


def cfg(tmp_path: Path) -> BridgeServiceSecretStorageConfig:
    parent = tmp_path / "secrets"
    parent.mkdir()
    config = BridgeServiceSecretStorageConfig(parent / "service-runtime", SID)
    config.root.mkdir()
    return config


def protect(data: bytes) -> bytes:
    return b"P" + bytes(value ^ 0x5A for value in data)


def unprotect(data: bytes) -> bytes:
    assert data.startswith(b"P")
    return bytes(value ^ 0x5A for value in data[1:])


def test_official_runtime_package_pin_is_exact():
    pin = module.TunnelClientPackagePin()
    pin.validate()
    assert pin.version == "v0.0.12"
    assert pin.asset_name == "tunnel-client-runtime-v0.0.12-windows-amd64.zip"
    assert pin.asset_size == 6_950_001
    assert pin.sha256 == "0721098f9edda72cc36f938adcb12cd6a0c49c6c0be7ad6ab6e412f966585f2e"
    assert pin.executable_name == "tunnel-client-runtime.exe"


def test_archive_verification_fails_closed_without_exact_official_bytes(tmp_path):
    archive = tmp_path / module.OPENAI_TUNNEL_CLIENT_ASSET
    archive.write_bytes(b"not-the-official-archive")
    with pytest.raises(module.SecureMcpTunnelIntegrityError, match="size differs"):
        module.TunnelClientPackagePin().verify_archive(archive)


def test_tunnel_runtime_api_key_is_machine_protected_create_once(tmp_path):
    config = cfg(tmp_path)
    store = module.TunnelRuntimeApiKeyStore(
        config,
        protector=protect,
        unprotector=unprotect,
    )
    store.provision(API_KEY)
    raw = config.tunnel_api_key_path.read_bytes()
    assert raw.startswith(module.TUNNEL_API_KEY_MAGIC)
    assert API_KEY.encode() not in raw
    assert store.load() == API_KEY
    store.provision(API_KEY)
    with pytest.raises(module.SecureMcpTunnelIntegrityError, match="different authority"):
        store.provision(API_KEY + "-rotated")


def test_tunnel_runtime_api_key_rejects_corrupt_envelope(tmp_path):
    config = cfg(tmp_path)
    config.tunnel_api_key_path.write_bytes(b"wrong-envelope")
    store = module.TunnelRuntimeApiKeyStore(
        config,
        protector=protect,
        unprotector=unprotect,
    )
    with pytest.raises(module.SecureMcpTunnelIntegrityError, match="invalid service-machine envelope"):
        store.load()


def test_launch_spec_is_runtime_only_and_secret_free(tmp_path):
    executable = tmp_path / module.OPENAI_TUNNEL_CLIENT_EXECUTABLE
    executable.write_bytes(b"placeholder")
    spec = module.build_tunnel_launch_spec(executable, TUNNEL_ID)
    assert spec.argv == (str(executable.absolute()), "run")
    assert spec.mcp_server_url == "http://127.0.0.1:8765/mcp"
    assert spec.readiness_path == "/readyz"
    assert "API_KEY" not in repr(spec)


def test_launch_spec_rejects_wrong_executable_and_tunnel_id(tmp_path):
    wrong = tmp_path / "tunnel-client.exe"
    wrong.write_bytes(b"placeholder")
    with pytest.raises(module.SecureMcpTunnelIntegrityError, match="basename"):
        module.build_tunnel_launch_spec(wrong, TUNNEL_ID)
    exact = tmp_path / module.OPENAI_TUNNEL_CLIENT_EXECUTABLE
    exact.write_bytes(b"placeholder")
    with pytest.raises(module.SecureMcpTunnelError, match="TUNNEL_ID"):
        module.build_tunnel_launch_spec(exact, "tunnel_not-authoritative")


def test_child_environment_is_minimal_and_never_uses_openai_api_key_fallback():
    child = module.build_tunnel_child_environment(
        {
            "SystemRoot": r"C:\\Windows",
            "ComSpec": r"C:\\Windows\\System32\\cmd.exe",
            "PATH": r"C:\\sensitive-bin",
            "OPENAI_API_KEY": "must-not-inherit",
            "OPENAI_ADMIN_KEY": "must-not-inherit",
            "UNRELATED_PASSWORD": "must-not-inherit",
        },
        tunnel_id=TUNNEL_ID,
        api_key=API_KEY,
    )
    assert child == {
        "SystemRoot": r"C:\\Windows",
        "ComSpec": r"C:\\Windows\\System32\\cmd.exe",
        "CONTROL_PLANE_TUNNEL_ID": TUNNEL_ID,
        "CONTROL_PLANE_API_KEY": API_KEY,
        "MCP_SERVER_URL": "http://127.0.0.1:8765/mcp",
    }
    assert "OPENAI_API_KEY" not in child
    assert "OPENAI_ADMIN_KEY" not in child
    assert "PATH" not in child


def test_readiness_requires_exact_http_200():
    assert module.tunnel_readiness_status_is_ready(200) is True
    for status in (0, 199, 201, 401, 403, 500, True):
        assert module.tunnel_readiness_status_is_ready(status) is False
