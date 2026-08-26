from __future__ import annotations

from copy import deepcopy

import pytest

from hms_gpt_vps.chatgpt_cimd_authority import (
    CHATGPT_CIMD_JWKS_URI,
    ChatGptCimdAuthorityError,
    qualify_chatgpt_cimd_authority_sync,
    require_chatgpt_cimd_client_id,
)

ISSUER = "https://issuer.example.test"
CLIENT_ID = "https://chatgpt.com/oauth/hms-vps-01/client.json"
AUTH_URL = "https://issuer.example.test/.well-known/oauth-authorization-server"
CALLBACK = "https://chatgpt.com/connector/oauth/callback-01"


def _auth():
    return {
        "issuer": ISSUER,
        "authorization_endpoint": "https://issuer.example.test/oauth/authorize",
        "token_endpoint": "https://issuer.example.test/oauth/token",
        "client_id_metadata_document_supported": True,
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "code_challenge_methods_supported": ["S256"],
    }


def _client():
    return {
        "client_id": CLIENT_ID,
        "client_name": "ChatGPT",
        "redirect_uris": [CALLBACK],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "jwks_uri": CHATGPT_CIMD_JWKS_URI,
    }


def _jwks():
    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "cimd-key-01",
                "use": "sig",
                "alg": "RS256",
                "n": "abcDEF012_-",
                "e": "AQAB",
            }
        ]
    }


class StableRequest:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, body, timeout_seconds, max_bytes):
        self.calls.append((method, url, body, timeout_seconds, max_bytes))
        if url == AUTH_URL:
            return deepcopy(_auth())
        if url == CLIENT_ID:
            return deepcopy(_client())
        if url == CHATGPT_CIMD_JWKS_URI:
            return deepcopy(_jwks())
        raise AssertionError(url)


def test_qualification_pins_chatgpt_cimd_private_key_jwt_metadata_but_keeps_token_and_ui_proof_false():
    request = StableRequest()
    evidence = qualify_chatgpt_cimd_authority_sync(
        ISSUER,
        CLIENT_ID,
        json_request=request,
        timeout_seconds=7,
    )
    assert evidence.client_id == CLIENT_ID
    assert evidence.redirect_uris == (CALLBACK,)
    assert evidence.jwks_kids == ("cimd-key-01",)
    assert evidence.chatgpt_cimd_metadata_authority_proven is True
    assert evidence.token_endpoint_private_key_jwt_exchange_proven is False
    assert evidence.chatgpt_app_oauth_client_proven is False
    assert evidence.chatgpt_ui_origin_proven is False
    assert [url for _, url, _, _, _ in request.calls] == [
        AUTH_URL,
        CLIENT_ID,
        CHATGPT_CIMD_JWKS_URI,
        AUTH_URL,
        CLIENT_ID,
        CHATGPT_CIMD_JWKS_URI,
    ]
    assert all(body is None for _, _, body, _, _ in request.calls)


@pytest.mark.parametrize(
    "value",
    [
        "http://chatgpt.com/oauth/x/client.json",
        "https://evil.example/oauth/x/client.json",
        "https://chatgpt.com:443/oauth/x/client.json",
        "https://chatgpt.com/oauth/x/client.json?mode=strong",
        "https://chatgpt.com/oauth/x/%2e%2e/client.json",
        "https://chatgpt.com/oauth/client.json",
    ],
)
def test_client_id_authority_is_exact_and_fail_closed(value):
    with pytest.raises(ChatGptCimdAuthorityError):
        require_chatgpt_cimd_client_id(value)


def test_qualification_rejects_client_metadata_self_binding_mismatch():
    def request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            return _auth()
        if url == CLIENT_ID:
            raw = _client()
            raw["client_id"] = "https://chatgpt.com/oauth/other/client.json"
            return raw
        return _jwks()
    with pytest.raises(ChatGptCimdAuthorityError, match="self-bind"):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=request)


@pytest.mark.parametrize(
    "mutator,match",
    [
        (lambda raw: raw.update(client_id_metadata_document_supported=False), "metadata documents"),
        (lambda raw: raw.update(token_endpoint_auth_methods_supported=["none"]), "private_key_jwt"),
        (lambda raw: raw.update(code_challenge_methods_supported=["plain"]), "S256"),
    ],
)
def test_qualification_rejects_issuer_without_required_cimd_private_key_jwt_pkce(mutator, match):
    def request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            raw = _auth()
            mutator(raw)
            return raw
        if url == CLIENT_ID:
            return _client()
        return _jwks()
    with pytest.raises(ChatGptCimdAuthorityError, match=match):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=request)


def test_qualification_rejects_chatgpt_metadata_without_stronger_auth_or_exact_jwks():
    def request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            return _auth()
        if url == CLIENT_ID:
            raw = _client()
            raw["token_endpoint_auth_methods_supported"] = ["none"]
            return raw
        return _jwks()
    with pytest.raises(ChatGptCimdAuthorityError, match="authentication methods"):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=request)

    def wrong_jwks_request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            return _auth()
        if url == CLIENT_ID:
            raw = _client()
            raw["jwks_uri"] = "https://chatgpt.com/oauth/other-jwks.json"
            return raw
        return _jwks()
    with pytest.raises(ChatGptCimdAuthorityError, match="JWKS URI"):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=wrong_jwks_request)


def test_qualification_rejects_private_jwk_material_and_jwks_drift():
    def private_request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            return _auth()
        if url == CLIENT_ID:
            return _client()
        raw = _jwks()
        raw["keys"][0]["d"] = "private"
        return raw
    with pytest.raises(ChatGptCimdAuthorityError, match="private key material"):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=private_request)

    count = {"jwks": 0}
    def drift_request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            return _auth()
        if url == CLIENT_ID:
            return _client()
        count["jwks"] += 1
        raw = _jwks()
        if count["jwks"] == 2:
            raw["keys"][0]["kid"] = "rotated-mid-proof"
        return raw
    with pytest.raises(ChatGptCimdAuthorityError, match="JWKS changed"):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=drift_request)


def test_qualification_rejects_legacy_only_redirect_metadata():
    def request(method, url, headers, body, timeout_seconds, max_bytes):
        if url == AUTH_URL:
            return _auth()
        if url == CLIENT_ID:
            raw = _client()
            raw["redirect_uris"] = [
                "https://chatgpt.com/connector_platform_oauth_redirect"
            ]
            return raw
        return _jwks()
    with pytest.raises(ChatGptCimdAuthorityError, match="current"):
        qualify_chatgpt_cimd_authority_sync(ISSUER, CLIENT_ID, json_request=request)
