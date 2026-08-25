from __future__ import annotations

from pathlib import Path

import pytest

import hms_gpt_vps.bridge_oauth_introspection_credential as module
from hms_gpt_vps.bridge_oauth_introspection_credential import (
    BridgeOAuthIntrospectionCredential,
    BridgeOAuthIntrospectionCredentialIntegrityError,
    BridgeOAuthIntrospectionCredentialStore,
    load_protected_bridge_oauth_introspection_credential,
)
from hms_gpt_vps.bridge_oauth_introspection_secret_storage import (
    build_bridge_oauth_introspection_secret_storage_script,
)


def _credential(issuer: str = "https://issuer.example.test/tenant") -> BridgeOAuthIntrospectionCredential:
    return BridgeOAuthIntrospectionCredential(issuer_url=issuer, client_id="hms-resource-server", client_secret="super-secret-value")


def test_client_secret_is_not_exposed_by_repr() -> None:
    rendered = repr(_credential())
    assert "super-secret-value" not in rendered
    assert "client_secret" not in rendered


def test_machine_credential_roundtrip_and_exact_issuer_binding(tmp_path: Path) -> None:
    path = tmp_path / "oauth.dpapi"
    store = BridgeOAuthIntrospectionCredentialStore(path, protector=lambda data: b"protected:" + data, unprotector=lambda data: data.removeprefix(b"protected:"))
    credential = _credential()
    store.save_create_only(credential)
    assert store.load(expected_issuer_url=credential.issuer_url) == credential
    with pytest.raises(BridgeOAuthIntrospectionCredentialIntegrityError, match="issuer differs"):
        store.load(expected_issuer_url="https://other.example.test")


def test_machine_credential_store_is_create_only(tmp_path: Path) -> None:
    path = tmp_path / "oauth.dpapi"
    store = BridgeOAuthIntrospectionCredentialStore(path, protector=lambda data: b"p" + data, unprotector=lambda data: data[1:])
    store.save_create_only(_credential())
    with pytest.raises(FileExistsError):
        store.save_create_only(_credential())


def test_oauth_secret_acl_script_pins_virtual_account_and_read_only_runtime() -> None:
    script = build_bridge_oauth_introspection_secret_storage_script(reconcile=False)
    assert "serviceAccount" in script and "HMSBridge" in script
    assert "oauth-introspection-client.service-machine.dpapi" in script
    assert "$reconcile = $false" in script
    assert "ReadAndExecute" in script and "FileSystemRights]::Read" in script and "FullControl" in script


def test_protected_load_sandwiches_config_and_secret_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    credential = _credential()
    monkeypatch.setattr(module, "prove_bridge_service_runtime_config_storage", lambda: events.append("config-proof") or {"config_sha256": "a" * 64})
    monkeypatch.setattr(module, "prove_bridge_oauth_introspection_secret_storage", lambda: events.append("secret-proof") or {"secret_sha256": "b" * 64})
    monkeypatch.setattr(module.BridgeOAuthIntrospectionCredentialStore, "load", lambda self, *, expected_issuer_url: events.append("secret-load") or credential)
    assert load_protected_bridge_oauth_introspection_credential(credential.issuer_url) is credential
    assert events == ["config-proof", "secret-proof", "secret-load", "secret-proof", "config-proof"]
