from __future__ import annotations

import pytest

from hms_gpt_vps.bridge_oauth_chatgpt_private_key_jwt_verifier import (
    BridgeOAuthChatGptClientAuthError,
    validate_chatgpt_private_key_jwt_introspection_extension,
)
from hms_gpt_vps.chatgpt_cimd_authority import CHATGPT_CIMD_JWKS_URI

CLIENT_ID = "https://chatgpt.com/oauth/hms/client.json"
KID = "chatgpt-key-01"


def attested() -> dict[str, object]:
    return {
        "client_auth_attestation": {
            "verified": True,
            "method": "private_key_jwt",
            "client_id": CLIENT_ID,
            "jwks_uri": CHATGPT_CIMD_JWKS_URI,
            "kid": KID,
        }
    }


def test_exact_token_specific_private_key_jwt_extension_passes() -> None:
    assert validate_chatgpt_private_key_jwt_introspection_extension(
        attested(),
        expected_client_id=CLIENT_ID,
        expected_jwks_kids=(KID, "chatgpt-key-02"),
    ) == ("private_key_jwt", KID)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verified", False),
        ("method", "none"),
        ("client_id", "https://chatgpt.com/oauth/other/client.json"),
        ("jwks_uri", "https://issuer.example.test/jwks.json"),
        ("kid", "unknown-key"),
    ],
)
def test_wrong_attestation_fact_fails_closed(field: str, value: object) -> None:
    raw = attested()
    raw["client_auth_attestation"][field] = value  # type: ignore[index]
    with pytest.raises(BridgeOAuthChatGptClientAuthError):
        validate_chatgpt_private_key_jwt_introspection_extension(
            raw,
            expected_client_id=CLIENT_ID,
            expected_jwks_kids=(KID,),
        )


def test_missing_attestation_fails_closed() -> None:
    with pytest.raises(BridgeOAuthChatGptClientAuthError):
        validate_chatgpt_private_key_jwt_introspection_extension(
            {},
            expected_client_id=CLIENT_ID,
            expected_jwks_kids=(KID,),
        )


def test_attestation_schema_drift_fails_closed() -> None:
    raw = attested()
    raw["client_auth_attestation"]["extra"] = True  # type: ignore[index]
    with pytest.raises(BridgeOAuthChatGptClientAuthError):
        validate_chatgpt_private_key_jwt_introspection_extension(
            raw,
            expected_client_id=CLIENT_ID,
            expected_jwks_kids=(KID,),
        )


def test_unqualified_or_duplicate_jwks_authority_fails_closed() -> None:
    for kids in ((), (KID, KID)):
        with pytest.raises(BridgeOAuthChatGptClientAuthError):
            validate_chatgpt_private_key_jwt_introspection_extension(
                attested(),
                expected_client_id=CLIENT_ID,
                expected_jwks_kids=kids,
            )
