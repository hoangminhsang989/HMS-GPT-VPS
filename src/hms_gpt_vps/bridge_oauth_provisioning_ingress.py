from __future__ import annotations

import json
import sys
from typing import BinaryIO

from .bridge_oauth_introspection_credential import (
    BridgeOAuthIntrospectionCredential,
    provision_bridge_oauth_introspection_credential,
)
from .bridge_oauth_introspection_secret_storage import (
    prove_bridge_oauth_introspection_secret_storage,
)
from .bridge_oauth_provisioning_identity import (
    prove_bridge_oauth_provisioning_identity,
)


_MAX_STDIN_BYTES = 12 * 1024
_INPUT_KEYS = frozenset({"issuer_url", "client_id", "client_secret"})


class BridgeOAuthProvisioningIngressError(RuntimeError):
    pass


def _strict_json_object(data: bytes) -> dict[str, object]:
    if not isinstance(data, bytes) or not data or len(data) > _MAX_STDIN_BYTES:
        raise BridgeOAuthProvisioningIngressError(
            "OAuth provisioning stdin size is invalid"
        )

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in items:
            if key in out:
                raise BridgeOAuthProvisioningIngressError(
                    "OAuth provisioning stdin contains duplicate fields"
                )
            out[key] = value
        return out

    try:
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeOAuthProvisioningIngressError(
            "OAuth provisioning stdin is not strict UTF-8 JSON"
        ) from exc
    if not isinstance(raw, dict) or frozenset(raw) != _INPUT_KEYS:
        raise BridgeOAuthProvisioningIngressError(
            "OAuth provisioning stdin fields differ from authority"
        )
    return raw


def read_bridge_oauth_provisioning_credential(
    stream: BinaryIO,
) -> BridgeOAuthIntrospectionCredential:
    if stream is None or not hasattr(stream, "read"):
        raise TypeError("stream must be a binary readable stream")
    data = stream.read(_MAX_STDIN_BYTES + 1)
    if not isinstance(data, bytes):
        raise TypeError("OAuth provisioning stdin must be binary")
    raw = _strict_json_object(data)
    credential = BridgeOAuthIntrospectionCredential(
        issuer_url=raw["issuer_url"],  # type: ignore[arg-type]
        client_id=raw["client_id"],  # type: ignore[arg-type]
        client_secret=raw["client_secret"],  # type: ignore[arg-type]
    )
    credential.validate()
    return credential


def provision_bridge_oauth_introspection_credential_from_stdin(
    stream: BinaryIO | None = None,
) -> dict[str, object]:
    # Security ordering is part of the authority: do not read stdin until an
    # elevated Administrator token and a stopped/manual HMSBridge are proven.
    before_read = prove_bridge_oauth_provisioning_identity()
    source = stream if stream is not None else sys.stdin.buffer
    credential = read_bridge_oauth_provisioning_credential(source)

    # Re-prove immediately before publication so SCM state cannot be changed
    # between the first gate and the secret write.
    before_publish = prove_bridge_oauth_provisioning_identity()
    if before_publish["service_sid"] != before_read["service_sid"]:
        raise BridgeOAuthProvisioningIngressError(
            "HMSBridge service SID changed before OAuth credential publication"
        )

    provision_bridge_oauth_introspection_credential(credential)

    storage = prove_bridge_oauth_introspection_secret_storage()
    after_publish = prove_bridge_oauth_provisioning_identity()
    if after_publish["service_sid"] != before_publish["service_sid"]:
        raise BridgeOAuthProvisioningIngressError(
            "HMSBridge service SID changed across OAuth credential publication"
        )

    # Deliberately return only non-secret evidence. Do not include credential
    # repr(), plaintext, ciphertext, Authorization headers, or POST bodies.
    return {
        "ready": True,
        "issuer_url": credential.issuer_url,
        "client_id": credential.client_id,
        "service_sid": after_publish["service_sid"],
        "service_state": after_publish["service_state"],
        "service_start_mode": after_publish["service_start_mode"],
        "secret_path": storage["secret_path"],
        "secret_sha256": storage["secret_sha256"],
        "secret_acl_exact": storage["secret_acl_exact"],
    }
