from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path

from .qualification_file_authority import (
    path_chain_has_redirect,
    read_file_pinned,
    require_existing_directory,
    write_json_create_only,
)


PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION = 1
MAX_PRINCIPAL_DISPATCH_INTENT_BYTES = 16 * 1024
_HEX_LOWER = frozenset("0123456789abcdef")
_INTENT_FIELDS = frozenset(
    {
        "schema_version",
        "principal_sha256",
        "pair_id",
        "session_id",
        "session_epoch",
        "instance_id",
        "request_id",
        "request_sha256",
        "command_sha256",
        "expires_at",
    }
)


class PrincipalDispatchIntentError(RuntimeError):
    pass


class PrincipalDispatchIntentConflictError(PrincipalDispatchIntentError):
    pass


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _canonical_sha256(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or value != value.lower()
        or any(char not in _HEX_LOWER for char in value)
    ):
        raise PrincipalDispatchIntentError(
            f"{name} must be canonical lowercase SHA-256"
        )
    return value


def _identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise PrincipalDispatchIntentError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise PrincipalDispatchIntentError(
            f"{name} contains unsupported characters"
        )
    return value


def _instance_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
    ):
        raise PrincipalDispatchIntentError("instance_id is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise PrincipalDispatchIntentError(
            "instance_id contains control characters"
        )
    return value


def _aware_utc(value: datetime, name: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() is None
    ):
        raise PrincipalDispatchIntentError(
            f"{name} must be timezone-aware"
        )
    return value.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return _aware_utc(value, "expires_at").isoformat().replace(
        "+00:00",
        "Z",
    )


def _parse_iso(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise PrincipalDispatchIntentError(
            "expires_at must be a timestamp string"
        )
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PrincipalDispatchIntentError(
            "expires_at is not a valid timestamp"
        ) from exc
    parsed = _aware_utc(parsed, "expires_at")
    if _iso(parsed) != value:
        raise PrincipalDispatchIntentError(
            "expires_at must be canonical UTC"
        )
    return parsed


def _strict_json_object(data: bytes) -> dict[str, object]:
    if not isinstance(data, bytes) or not data:
        raise PrincipalDispatchIntentError(
            "dispatch intent must contain JSON bytes"
        )
    if len(data) > MAX_PRINCIPAL_DISPATCH_INTENT_BYTES:
        raise PrincipalDispatchIntentError(
            "dispatch intent exceeds size bound"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PrincipalDispatchIntentError(
            "dispatch intent is not UTF-8"
        ) from exc

    def no_duplicates(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise PrincipalDispatchIntentError(
                    f"dispatch intent has duplicate JSON key: {key}"
                )
            result[key] = value
        return result

    try:
        payload = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise PrincipalDispatchIntentError(
            "dispatch intent is not valid JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise PrincipalDispatchIntentError(
            "dispatch intent must be a JSON object"
        )
    return payload


@dataclass(frozen=True)
class PrincipalDispatchIntent:
    schema_version: int
    principal_sha256: str
    pair_id: str
    session_id: str
    session_epoch: int
    instance_id: str
    request_id: str
    request_sha256: str
    command_sha256: str
    expires_at: datetime

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != PRINCIPAL_DISPATCH_INTENT_SCHEMA_VERSION
        ):
            raise PrincipalDispatchIntentError(
                "unsupported dispatch intent schema"
            )
        _canonical_sha256(self.principal_sha256, "principal_sha256")
        _identifier(self.pair_id, "pair_id")
        _identifier(self.session_id, "session_id")
        if (
            isinstance(self.session_epoch, bool)
            or not isinstance(self.session_epoch, int)
            or self.session_epoch < 1
        ):
            raise PrincipalDispatchIntentError(
                "session_epoch must be a positive integer"
            )
        _instance_id(self.instance_id)
        _identifier(self.request_id, "request_id")
        _canonical_sha256(self.request_sha256, "request_sha256")
        _canonical_sha256(self.command_sha256, "command_sha256")
        _aware_utc(self.expires_at, "expires_at")

    def to_mapping(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "principal_sha256": self.principal_sha256,
            "pair_id": self.pair_id,
            "session_id": self.session_id,
            "session_epoch": self.session_epoch,
            "instance_id": self.instance_id,
            "request_id": self.request_id,
            "request_sha256": self.request_sha256,
            "command_sha256": self.command_sha256,
            "expires_at": _iso(self.expires_at),
        }

    @classmethod
    def from_bytes(cls, data: bytes) -> "PrincipalDispatchIntent":
        payload = _strict_json_object(data)
        if frozenset(payload.keys()) != _INTENT_FIELDS:
            raise PrincipalDispatchIntentError(
                "dispatch intent fields do not match schema"
            )
        schema = payload["schema_version"]
        epoch = payload["session_epoch"]
        if isinstance(schema, bool) or not isinstance(schema, int):
            raise PrincipalDispatchIntentError(
                "dispatch intent schema_version must be an integer"
            )
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise PrincipalDispatchIntentError(
                "dispatch intent session_epoch must be an integer"
            )
        intent = cls(
            schema_version=schema,
            principal_sha256=_canonical_sha256(
                payload["principal_sha256"],
                "principal_sha256",
            ),
            pair_id=_identifier(payload["pair_id"], "pair_id"),
            session_id=_identifier(payload["session_id"], "session_id"),
            session_epoch=epoch,
            instance_id=_instance_id(payload["instance_id"]),
            request_id=_identifier(payload["request_id"], "request_id"),
            request_sha256=_canonical_sha256(
                payload["request_sha256"],
                "request_sha256",
            ),
            command_sha256=_canonical_sha256(
                payload["command_sha256"],
                "command_sha256",
            ),
            expires_at=_parse_iso(payload["expires_at"]),
        )
        intent.validate()
        return intent


@dataclass(frozen=True)
class PrincipalDispatchStage:
    intent: PrincipalDispatchIntent
    is_new: bool


class PrincipalDispatchIntentStore:
    """Create-only, digest-only authority proving Agent-dispatch ownership.

    One immutable file is retained per session/request id. It contains no raw
    session token, pairing token, principal subject, request parameters or file
    content. Publication always precedes the idempotency claim so a later
    unresolved claim can be resumed only when an exact older dispatch intent is
    already durable.
    """

    def __init__(self, root: Path) -> None:
        self.root = require_existing_directory(
            root,
            label="principal dispatch intent root",
        )
        self._root_identity = self.root.stat()

    def _assert_root(self) -> None:
        current = require_existing_directory(
            self.root,
            label="principal dispatch intent root",
        ).stat()
        if not _same_file_identity(self._root_identity, current):
            raise PrincipalDispatchIntentError(
                "principal dispatch intent root identity changed"
            )

    @staticmethod
    def _filename(intent: PrincipalDispatchIntent) -> str:
        intent.validate()
        identity = b"\x00".join(
            (
                intent.session_id.encode("ascii"),
                intent.request_id.encode("ascii"),
                intent.instance_id.encode("utf-8"),
            )
        )
        return "dispatch-" + hashlib.sha256(identity).hexdigest() + ".json"

    def _path(self, intent: PrincipalDispatchIntent) -> Path:
        return self.root / self._filename(intent)

    def _load_path(self, path: Path) -> PrincipalDispatchIntent:
        self._assert_root()
        if path_chain_has_redirect(path):
            raise PrincipalDispatchIntentError(
                "dispatch intent path traverses a link or reparse point"
            )
        try:
            data = read_file_pinned(
                path,
                max_bytes=MAX_PRINCIPAL_DISPATCH_INTENT_BYTES,
                label="principal dispatch intent",
            )
        except (PermissionError, RuntimeError, ValueError) as exc:
            raise PrincipalDispatchIntentError(
                "dispatch intent authority could not be read safely"
            ) from exc
        intent = PrincipalDispatchIntent.from_bytes(data)
        self._assert_root()
        return intent

    def load(
        self,
        template: PrincipalDispatchIntent,
    ) -> PrincipalDispatchIntent | None:
        template.validate()
        path = self._path(template)
        try:
            return self._load_path(path)
        except FileNotFoundError:
            return None

    def stage(
        self,
        intent: PrincipalDispatchIntent,
    ) -> PrincipalDispatchStage:
        intent.validate()
        self._assert_root()
        path = self._path(intent)
        existing = self.load(intent)
        if existing is not None:
            if existing != intent:
                raise PrincipalDispatchIntentConflictError(
                    "dispatch intent already exists with different authority"
                )
            return PrincipalDispatchStage(intent=existing, is_new=False)

        try:
            write_json_create_only(
                path,
                intent.to_mapping(),
                max_bytes=MAX_PRINCIPAL_DISPATCH_INTENT_BYTES,
                label="principal dispatch intent",
            )
            created = True
        except FileExistsError:
            created = False

        published = self._load_path(path)
        if published != intent:
            raise PrincipalDispatchIntentConflictError(
                "published dispatch intent differs from requested authority"
            )
        self._assert_root()
        return PrincipalDispatchStage(intent=published, is_new=created)
