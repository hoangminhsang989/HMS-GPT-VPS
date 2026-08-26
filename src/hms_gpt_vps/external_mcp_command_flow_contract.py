from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json


EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION = 1
MAX_EXTERNAL_MCP_READ_CHALLENGE_SECONDS = 900
MAX_QUALIFICATION_PATH_CHARS = 1024
HEX_LOWER = frozenset("0123456789abcdef")
SAFE_IDENTIFIER_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)
READ_ACTION = "workspace.read"
READ_RESPONSE_FIELDS = frozenset(
    {"ok", "path", "encoding", "content", "size", "sha256", "modified_utc"}
)
RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "instance_id",
        "request_id",
        "command_sha256",
        "result_sha256",
    }
)


class ExternalMcpCommandFlowObservationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalMcpReadChallenge:
    schema_version: int
    challenge_id: str
    source_commit: str
    instance_id: str
    request_id: str
    path: str
    expected_content_sha256: str
    issued_at: datetime
    expires_at: datetime

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != EXTERNAL_MCP_READ_CHALLENGE_SCHEMA_VERSION
        ):
            raise ExternalMcpCommandFlowObservationError(
                "unsupported external MCP read challenge schema"
            )
        identifier(self.challenge_id, "challenge_id")
        canonical_git_sha1(self.source_commit)
        identifier(self.instance_id, "instance_id")
        identifier(self.request_id, "request_id")
        qualification_path(self.path)
        canonical_sha256(
            self.expected_content_sha256,
            "expected_content_sha256",
        )
        issued = aware_utc(self.issued_at, "issued_at")
        expires = aware_utc(self.expires_at, "expires_at")
        if expires <= issued:
            raise ExternalMcpCommandFlowObservationError(
                "challenge expires_at must follow issued_at"
            )
        if (expires - issued) > timedelta(
            seconds=MAX_EXTERNAL_MCP_READ_CHALLENGE_SECONDS
        ):
            raise ExternalMcpCommandFlowObservationError(
                "challenge lifetime exceeds qualification bound"
            )


def identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ExternalMcpCommandFlowObservationError(f"{name} is invalid")
    if any(char not in SAFE_IDENTIFIER_CHARS for char in value):
        raise ExternalMcpCommandFlowObservationError(
            f"{name} contains unsupported characters"
        )
    return value


def canonical_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in HEX_LOWER for char in value)
    ):
        raise ExternalMcpCommandFlowObservationError(
            f"{name} must be canonical lowercase SHA-256"
        )
    return value


def canonical_git_sha1(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or value != value.lower()
        or any(char not in HEX_LOWER for char in value)
    ):
        raise ExternalMcpCommandFlowObservationError(
            "source_commit must be canonical lowercase Git SHA-1"
        )
    return value


def qualification_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > MAX_QUALIFICATION_PATH_CHARS
        or value.startswith("/")
        or "\\" in value
        or ":" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
    ):
        raise ExternalMcpCommandFlowObservationError(
            "qualification path must be a canonical relative forward-slash path"
        )
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ExternalMcpCommandFlowObservationError(
            "qualification path contains an unsafe segment"
        )
    return value


def aware_utc(value: object, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise ExternalMcpCommandFlowObservationError(
            f"{name} must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def canonical_json_sha256(value: object) -> str:
    try:
        raw = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ExternalMcpCommandFlowObservationError(
            "observed authority is not canonical JSON-safe"
        ) from exc
    return hashlib.sha256(raw).hexdigest()
