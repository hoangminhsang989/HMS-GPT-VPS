from __future__ import annotations

import io
import json

import pytest

import hms_gpt_vps.bridge_oauth_provisioning_ingress as mod


SID = "S-1-5-80-1-2-3-4-5"


def identity():
    return {
        "elevated_administrator": True,
        "process_sid": "S-1-5-21-1000",
        "identity_name": r"HOST\Admin",
        "service_name": "HMSBridge",
        "service_start_name": r"NT SERVICE\HMSBridge",
        "service_start_mode": "Manual",
        "service_state": "Stopped",
        "service_sid": SID,
    }


class RecordingStream(io.BytesIO):
    def __init__(self, data: bytes):
        super().__init__(data)
        self.read_called = False

    def read(self, *args, **kwargs):
        self.read_called = True
        return super().read(*args, **kwargs)


def payload(secret="top-secret"):
    return json.dumps(
        {
            "issuer_url": "https://issuer.example/oauth",
            "client_id": "hms-bridge",
            "client_secret": secret,
        }
    ).encode()


def test_preflight_failure_happens_before_stdin_read(monkeypatch):
    stream = RecordingStream(payload())
    monkeypatch.setattr(
        mod,
        "prove_bridge_oauth_provisioning_identity",
        lambda: (_ for _ in ()).throw(PermissionError("not elevated")),
    )
    with pytest.raises(PermissionError):
        mod.provision_bridge_oauth_introspection_credential_from_stdin(stream)
    assert stream.read_called is False


def test_successful_publication_returns_no_secret(monkeypatch):
    stream = RecordingStream(payload())
    calls = []
    monkeypatch.setattr(
        mod, "prove_bridge_oauth_provisioning_identity",
        lambda: calls.append("proof") or identity(),
    )
    monkeypatch.setattr(
        mod,
        "provision_bridge_oauth_introspection_credential",
        lambda credential: calls.append(("publish", credential.client_id)),
    )
    monkeypatch.setattr(
        mod,
        "prove_bridge_oauth_introspection_secret_storage",
        lambda: {
            "secret_path": r"C:\ProgramData\HMS-GPT-VPS\Bridge\oauth-introspection-client.service-machine.dpapi",
            "secret_sha256": "a" * 64,
            "secret_acl_exact": True,
        },
    )
    result = mod.provision_bridge_oauth_introspection_credential_from_stdin(stream)
    assert calls == ["proof", "proof", ("publish", "hms-bridge"), "proof"]
    rendered = repr(result)
    assert "top-secret" not in rendered
    assert result["ready"] is True
    assert result["service_state"] == "Stopped"


def test_duplicate_fields_fail_closed():
    data = (
        b'{"issuer_url":"https://issuer.example","client_id":"a",'
        b'"client_id":"b","client_secret":"s"}'
    )
    with pytest.raises(mod.BridgeOAuthProvisioningIngressError):
        mod.read_bridge_oauth_provisioning_credential(io.BytesIO(data))


def test_extra_fields_fail_closed():
    raw = json.loads(payload())
    raw["unexpected"] = True
    with pytest.raises(mod.BridgeOAuthProvisioningIngressError):
        mod.read_bridge_oauth_provisioning_credential(
            io.BytesIO(json.dumps(raw).encode())
        )


def test_oversized_stdin_fails_closed():
    with pytest.raises(mod.BridgeOAuthProvisioningIngressError):
        mod.read_bridge_oauth_provisioning_credential(
            io.BytesIO(b"x" * (mod._MAX_STDIN_BYTES + 1))
        )
