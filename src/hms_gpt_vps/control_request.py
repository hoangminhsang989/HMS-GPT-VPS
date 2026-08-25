from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping

from .control_session import ControlSessionRecord
from .control_session_store import ControlSessionStore


CONTROL_REQUEST_SCHEMA_VERSION = 1
MAX_CONTROL_REQUEST_BYTES = 256 * 1024
CONTROL_ACTION_SCOPES = {
    "workspace.read": "workspace.read",
    "workspace.write": "workspace.write",
    "process.test": "process.test",
    "git.status": "git.status",
    "audit.read": "audit.read",
}
_CONTROL_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "instance_id",
        "session_id",
        "action",
        "params",
    }
)


class ControlRequestError(ValueError):
    pass


def _validate_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ControlRequestError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise ControlRequestError(f"{name} contains unsupported characters")
    return value


def _validate_instance_id(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > 128
    ):
        raise ControlRequestError("instance_id is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ControlRequestError("instance_id contains control characters")
    return value


def _validate_action(value: object) -> str:
    if not isinstance(value, str) or value not in CONTROL_ACTION_SCOPES:
        raise ControlRequestError(f"unsupported control action: {value!r}")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ControlRequestError("control request must contain JSON-safe values") from exc
    if len(encoded) > MAX_CONTROL_REQUEST_BYTES:
        raise ControlRequestError("control request exceeds maximum encoded size")
    return encoded


@dataclass(frozen=True)
class ControlRequest:
    schema_version: int
    request_id: str
    instance_id: str
    session_id: str
    action: str
    params: Mapping[str, Any]

    def validate(self) -> None:
        if (
            isinstance(self.schema_version, bool)
            or not isinstance(self.schema_version, int)
            or self.schema_version != CONTROL_REQUEST_SCHEMA_VERSION
        ):
            raise ControlRequestError(
                f"unsupported control request schema: {self.schema_version!r}"
            )
        _validate_identifier(self.request_id, "request_id")
        _validate_instance_id(self.instance_id)
        _validate_identifier(self.session_id, "session_id")
        _validate_action(self.action)
        if not isinstance(self.params, Mapping):
            raise ControlRequestError("control request params must be an object")
        _canonical_json(self.to_dict(validate=False))

    @property
    def required_scope(self) -> str:
        action = _validate_action(self.action)
        return CONTROL_ACTION_SCOPES[action]

    def to_dict(self, *, validate: bool = True) -> dict[str, Any]:
        if validate:
            self.validate()
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "instance_id": self.instance_id,
            "session_id": self.session_id,
            "action": self.action,
            "params": dict(self.params),
        }

    def request_sha256(self) -> str:
        self.validate()
        return hashlib.sha256(
            _canonical_json(self.to_dict(validate=False))
        ).hexdigest()

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ControlRequest":
        if not isinstance(payload, Mapping):
            raise ControlRequestError("control request must be an object")
        if frozenset(payload.keys()) != _CONTROL_REQUEST_FIELDS:
            raise ControlRequestError(
                "control request fields do not match schema"
            )
        schema_version = payload["schema_version"]
        if isinstance(schema_version, bool) or not isinstance(schema_version, int):
            raise ControlRequestError(
                "control request schema_version must be an integer"
            )
        request_id = _validate_identifier(payload["request_id"], "request_id")
        instance_id = _validate_instance_id(payload["instance_id"])
        session_id = _validate_identifier(payload["session_id"], "session_id")
        action = _validate_action(payload["action"])
        params = payload["params"]
        if not isinstance(params, Mapping):
            raise ControlRequestError("control request params must be an object")
        request = cls(
            schema_version=schema_version,
            request_id=request_id,
            instance_id=instance_id,
            session_id=session_id,
            action=action,
            params=dict(params),
        )
        request.validate()
        return request


def authorize_control_request(
    request: ControlRequest,
    session_token: str,
    session_store: ControlSessionStore,
    *,
    now=None,
) -> ControlSessionRecord:
    """Authenticate one request without persisting or logging the raw token."""
    request.validate()
    return session_store.verify(
        request.session_id,
        session_token,
        instance_id=request.instance_id,
        required_scope=request.required_scope,
        now=now,
    )
