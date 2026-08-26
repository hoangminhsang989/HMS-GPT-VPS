from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit

from .bridge_oauth_http import (
    DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
    SyncJsonRequest,
    authorization_server_metadata_url,
    request_oauth_json_sync,
    require_https_endpoint,
    require_https_issuer,
    require_oauth_timeout,
)

CHATGPT_CIMD_ORIGIN = "https://chatgpt.com"
CHATGPT_CIMD_JWKS_URI = "https://chatgpt.com/oauth/jwks.json"
MAX_CHATGPT_CIMD_BYTES = 5 * 1024
MAX_CHATGPT_JWKS_BYTES = 32 * 1024
_PRIVATE_KEY_JWT = "private_key_jwt"
_ALLOWED_CHATGPT_CIMD_AUTH_METHODS = frozenset({"none", _PRIVATE_KEY_JWT})
_CLIENT_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~-]+$")
_CURRENT_CALLBACK_RE = re.compile(r"^/connector/oauth/[A-Za-z0-9._~-]+$")
_LEGACY_CALLBACK_PATH = "/connector_platform_oauth_redirect"
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class ChatGptCimdAuthorityError(RuntimeError):
    pass


def _require_text(value: object, name: str, *, max_length: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ChatGptCimdAuthorityError(f"{name} must be canonical non-empty text")
    return value


def require_chatgpt_cimd_client_id(value: object) -> str:
    client_id = _require_text(value, "ChatGPT CIMD client_id", max_length=512)
    parsed = urlsplit(client_id)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "chatgpt.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD client_id must use the exact canonical chatgpt.com HTTPS authority"
        )
    segments = parsed.path.split("/")
    if (
        len(segments) < 4
        or segments[0] != ""
        or segments[1] != "oauth"
        or segments[-1] != "client.json"
        or any(not segment for segment in segments[1:])
        or any(segment in {".", ".."} for segment in segments[1:])
        or any(
            not _CLIENT_SEGMENT_RE.fullmatch(segment)
            for segment in segments[2:-1]
        )
    ):
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD client_id path is outside the reviewed /oauth/.../client.json authority"
        )
    return client_id


def _require_string_list(
    value: object,
    name: str,
    *,
    max_items: int = 32,
    max_item_length: int = 2048,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > max_items:
        raise ChatGptCimdAuthorityError(f"{name} must be a bounded non-empty list")
    out: list[str] = []
    for item in value:
        out.append(_require_text(item, name, max_length=max_item_length))
    if len(set(out)) != len(out):
        raise ChatGptCimdAuthorityError(f"{name} must not contain duplicates")
    return tuple(out)


def _require_chatgpt_redirect_uri(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "chatgpt.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "%" in parsed.path
    ):
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD redirect URI must use exact chatgpt.com HTTPS authority"
        )
    if parsed.path == _LEGACY_CALLBACK_PATH:
        return value
    if _CURRENT_CALLBACK_RE.fullmatch(parsed.path) is None:
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD redirect URI is outside the reviewed connector callback authority"
        )
    return value


def _canonical_sha256(value: object) -> str:
    try:
        data = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ChatGptCimdAuthorityError("authority JSON is not canonicalizable") from exc
    return hashlib.sha256(data).hexdigest()


def _validate_authorization_server_metadata(
    issuer_url: str,
    raw: Mapping[str, Any],
) -> dict[str, object]:
    if raw.get("issuer") != issuer_url:
        raise ChatGptCimdAuthorityError(
            "authorization-server metadata issuer differs from configured authority"
        )
    if raw.get("client_id_metadata_document_supported") is not True:
        raise ChatGptCimdAuthorityError(
            "authorization server does not explicitly support client ID metadata documents"
        )
    auth_methods = _require_string_list(
        raw.get("token_endpoint_auth_methods_supported"),
        "token_endpoint_auth_methods_supported",
        max_items=32,
        max_item_length=128,
    )
    if _PRIVATE_KEY_JWT not in auth_methods:
        raise ChatGptCimdAuthorityError(
            "authorization server does not explicitly support private_key_jwt"
        )
    pkce_methods = _require_string_list(
        raw.get("code_challenge_methods_supported"),
        "code_challenge_methods_supported",
        max_items=16,
        max_item_length=64,
    )
    if "S256" not in pkce_methods:
        raise ChatGptCimdAuthorityError(
            "authorization server does not explicitly support S256 PKCE"
        )
    authorization_endpoint = require_https_endpoint(
        raw.get("authorization_endpoint"),
        "authorization_endpoint",
    )
    token_endpoint = require_https_endpoint(
        raw.get("token_endpoint"),
        "token_endpoint",
    )
    return {
        "issuer": issuer_url,
        "client_id_metadata_document_supported": True,
        "token_endpoint_auth_methods_supported": list(auth_methods),
        "code_challenge_methods_supported": list(pkce_methods),
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
    }


def _validate_chatgpt_cimd(
    expected_client_id: str,
    raw: Mapping[str, Any],
) -> dict[str, object]:
    if raw.get("client_id") != expected_client_id:
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD client_id does not self-bind to the metadata document URL"
        )
    client_name = _require_text(
        raw.get("client_name"),
        "ChatGPT CIMD client_name",
        max_length=256,
    )
    redirect_uris = tuple(
        _require_chatgpt_redirect_uri(value)
        for value in _require_string_list(
            raw.get("redirect_uris"),
            "ChatGPT CIMD redirect_uris",
            max_items=16,
            max_item_length=2048,
        )
    )
    if not any(
        _CURRENT_CALLBACK_RE.fullmatch(urlsplit(value).path) is not None
        for value in redirect_uris
    ):
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD does not advertise a current /connector/oauth/{callback_id} redirect"
        )
    auth_methods = _require_string_list(
        raw.get("token_endpoint_auth_methods_supported"),
        "ChatGPT CIMD token_endpoint_auth_methods_supported",
        max_items=8,
        max_item_length=128,
    )
    if frozenset(auth_methods) != _ALLOWED_CHATGPT_CIMD_AUTH_METHODS:
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD authentication methods differ from reviewed OpenAI authority"
        )
    jwks_uri = require_https_endpoint(raw.get("jwks_uri"), "ChatGPT CIMD jwks_uri")
    if jwks_uri != CHATGPT_CIMD_JWKS_URI:
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD JWKS URI differs from reviewed OpenAI authority"
        )
    return {
        "client_id": expected_client_id,
        "client_name": client_name,
        "redirect_uris": list(redirect_uris),
        "token_endpoint_auth_methods_supported": list(auth_methods),
        "jwks_uri": jwks_uri,
    }


def _validate_chatgpt_jwks(raw: Mapping[str, Any]) -> tuple[str, ...]:
    keys = raw.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 32:
        raise ChatGptCimdAuthorityError("ChatGPT JWKS keys must be a bounded non-empty list")
    kids: list[str] = []
    for key in keys:
        if not isinstance(key, dict):
            raise ChatGptCimdAuthorityError("ChatGPT JWKS key must be an object")
        if _PRIVATE_JWK_MEMBERS.intersection(key):
            raise ChatGptCimdAuthorityError("ChatGPT JWKS unexpectedly contains private key material")
        kid = _require_text(key.get("kid"), "ChatGPT JWKS kid", max_length=256)
        kty = _require_text(key.get("kty"), "ChatGPT JWKS kty", max_length=32)
        if kty not in {"RSA", "EC", "OKP"}:
            raise ChatGptCimdAuthorityError("ChatGPT JWKS kty is outside reviewed signing-key types")
        if key.get("use") != "sig":
            raise ChatGptCimdAuthorityError("ChatGPT JWKS key is not explicitly a signing key")
        alg = _require_text(key.get("alg"), "ChatGPT JWKS alg", max_length=64)
        if alg == "none" or alg.startswith("HS"):
            raise ChatGptCimdAuthorityError("ChatGPT JWKS uses a non-public-key signing algorithm")
        if kty == "RSA":
            _require_text(key.get("n"), "ChatGPT RSA modulus", max_length=8192)
            _require_text(key.get("e"), "ChatGPT RSA exponent", max_length=64)
        elif kty == "EC":
            _require_text(key.get("crv"), "ChatGPT EC curve", max_length=64)
            _require_text(key.get("x"), "ChatGPT EC x", max_length=1024)
            _require_text(key.get("y"), "ChatGPT EC y", max_length=1024)
        else:
            _require_text(key.get("crv"), "ChatGPT OKP curve", max_length=64)
            _require_text(key.get("x"), "ChatGPT OKP x", max_length=1024)
        kids.append(kid)
    if len(set(kids)) != len(kids):
        raise ChatGptCimdAuthorityError("ChatGPT JWKS kid values must be unique")
    return tuple(kids)


@dataclass(frozen=True)
class ChatGptCimdAuthorityEvidence:
    issuer_url: str
    client_id: str
    client_name: str
    redirect_uris: tuple[str, ...]
    jwks_uri: str
    jwks_kids: tuple[str, ...]
    authorization_server_authority_sha256: str
    client_metadata_authority_sha256: str
    jwks_sha256: str
    chatgpt_cimd_metadata_authority_proven: bool = True
    token_endpoint_private_key_jwt_exchange_proven: bool = False
    chatgpt_app_oauth_client_proven: bool = False
    chatgpt_ui_origin_proven: bool = False

    def validate(self) -> None:
        require_https_issuer(self.issuer_url)
        require_chatgpt_cimd_client_id(self.client_id)
        _require_text(self.client_name, "ChatGPT CIMD client_name", max_length=256)
        if not self.redirect_uris:
            raise ChatGptCimdAuthorityError("ChatGPT CIMD redirect authority is missing")
        for value in self.redirect_uris:
            _require_chatgpt_redirect_uri(value)
        if self.jwks_uri != CHATGPT_CIMD_JWKS_URI:
            raise ChatGptCimdAuthorityError("ChatGPT CIMD evidence JWKS URI differs from authority")
        if not self.jwks_kids or len(set(self.jwks_kids)) != len(self.jwks_kids):
            raise ChatGptCimdAuthorityError("ChatGPT CIMD evidence JWKS key identity is invalid")
        for digest in (
            self.authorization_server_authority_sha256,
            self.client_metadata_authority_sha256,
            self.jwks_sha256,
        ):
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or digest != digest.lower()
                or any(char not in "0123456789abcdef" for char in digest)
            ):
                raise ChatGptCimdAuthorityError("ChatGPT CIMD evidence digest is invalid")
        if self.chatgpt_cimd_metadata_authority_proven is not True:
            raise ChatGptCimdAuthorityError("ChatGPT CIMD metadata authority proof is false")
        if self.token_endpoint_private_key_jwt_exchange_proven is not False:
            raise ChatGptCimdAuthorityError(
                "metadata qualification must not claim private_key_jwt token exchange"
            )
        if self.chatgpt_app_oauth_client_proven is not False:
            raise ChatGptCimdAuthorityError(
                "metadata qualification must not claim token-specific ChatGPT OAuth client proof"
            )
        if self.chatgpt_ui_origin_proven is not False:
            raise ChatGptCimdAuthorityError(
                "metadata qualification must not claim ChatGPT UI origin"
            )

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "issuer_url": self.issuer_url,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "redirect_uris": list(self.redirect_uris),
            "jwks_uri": self.jwks_uri,
            "jwks_kids": list(self.jwks_kids),
            "authorization_server_authority_sha256": self.authorization_server_authority_sha256,
            "client_metadata_authority_sha256": self.client_metadata_authority_sha256,
            "jwks_sha256": self.jwks_sha256,
            "chatgpt_cimd_metadata_authority_proven": True,
            "token_endpoint_private_key_jwt_exchange_proven": False,
            "chatgpt_app_oauth_client_proven": False,
            "chatgpt_ui_origin_proven": False,
        }


def qualify_chatgpt_cimd_authority_sync(
    issuer_url: str,
    expected_client_id: str,
    *,
    json_request: SyncJsonRequest = request_oauth_json_sync,
    timeout_seconds: int = DEFAULT_OAUTH_HTTP_TIMEOUT_SECONDS,
) -> ChatGptCimdAuthorityEvidence:
    issuer = require_https_issuer(issuer_url)
    client_id = require_chatgpt_cimd_client_id(expected_client_id)
    require_oauth_timeout(timeout_seconds)
    if not callable(json_request):
        raise TypeError("json_request must be callable")

    auth_url = authorization_server_metadata_url(issuer)
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "HMS-GPT-VPS ChatGPT CIMD qualification",
    }

    auth_before = _validate_authorization_server_metadata(
        issuer,
        json_request(
            "GET",
            auth_url,
            request_headers,
            None,
            timeout_seconds,
            MAX_CHATGPT_CIMD_BYTES,
        ),
    )
    client_before = _validate_chatgpt_cimd(
        client_id,
        json_request(
            "GET",
            client_id,
            request_headers,
            None,
            timeout_seconds,
            MAX_CHATGPT_CIMD_BYTES,
        ),
    )
    jwks_before_raw = json_request(
        "GET",
        CHATGPT_CIMD_JWKS_URI,
        request_headers,
        None,
        timeout_seconds,
        MAX_CHATGPT_JWKS_BYTES,
    )
    kids_before = _validate_chatgpt_jwks(jwks_before_raw)

    auth_after = _validate_authorization_server_metadata(
        issuer,
        json_request(
            "GET",
            auth_url,
            request_headers,
            None,
            timeout_seconds,
            MAX_CHATGPT_CIMD_BYTES,
        ),
    )
    client_after = _validate_chatgpt_cimd(
        client_id,
        json_request(
            "GET",
            client_id,
            request_headers,
            None,
            timeout_seconds,
            MAX_CHATGPT_CIMD_BYTES,
        ),
    )
    jwks_after_raw = json_request(
        "GET",
        CHATGPT_CIMD_JWKS_URI,
        request_headers,
        None,
        timeout_seconds,
        MAX_CHATGPT_JWKS_BYTES,
    )
    kids_after = _validate_chatgpt_jwks(jwks_after_raw)

    auth_sha = _canonical_sha256(auth_before)
    client_sha = _canonical_sha256(client_before)
    jwks_sha = _canonical_sha256(jwks_before_raw)
    if _canonical_sha256(auth_after) != auth_sha:
        raise ChatGptCimdAuthorityError(
            "authorization-server client authority changed across qualification"
        )
    if _canonical_sha256(client_after) != client_sha:
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD metadata changed across qualification"
        )
    if _canonical_sha256(jwks_after_raw) != jwks_sha or kids_after != kids_before:
        raise ChatGptCimdAuthorityError(
            "ChatGPT CIMD JWKS changed across qualification"
        )

    evidence = ChatGptCimdAuthorityEvidence(
        issuer_url=issuer,
        client_id=client_id,
        client_name=str(client_before["client_name"]),
        redirect_uris=tuple(client_before["redirect_uris"]),  # type: ignore[arg-type]
        jwks_uri=str(client_before["jwks_uri"]),
        jwks_kids=kids_before,
        authorization_server_authority_sha256=auth_sha,
        client_metadata_authority_sha256=client_sha,
        jwks_sha256=jwks_sha,
    )
    evidence.validate()
    return evidence
