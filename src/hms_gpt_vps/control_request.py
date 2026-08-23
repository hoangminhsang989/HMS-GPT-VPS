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


class ControlRequestError(ValueError):
    pass


def _validate_identifier(value: str, name: str) -> None:
    if not value or len(value) > 128:
        raise ControlRequestError(f"{name} is invalid")
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    if any(char not in allowed for char in value):
        raise ControlRequestError(f"{name} contains unsupported characters")


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
        if self.schema_version != CONTROL_REQUEST_SCHEMA_VERSION:
            raise ControlRequestError(
                f"unsupported control request schema: {self.schema_version}"
            )
        _validate_identifier(self.request_id, "request_id")
        if not self.instance_id.strip() or len(self.instance_id) > 128:
            raise ControlRequestError("instance_id is invalid")
        _validate_identifier(self.session_id, "session_id")
        if self.action not in CONTROL_ACTION_SCOPES:
            raise ControlRequestError(f"unsupported control action: {self.action}")
        if not isinstance(self.params, Mapping):
            raise ControlRequestError("control request params must be an object")
        _canonical_json(self.to_dict(validate=False))

    @property
    def required_scope(self) -> str:
        try:
            return CONTROL_ACTION_SCOPES[self.action]
        except KeyError as exc:
            raise ControlRequestError(f"unsupported control action: {self.action}") from exc

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
        return hashlib.sha256(_canonical_json(self.to_dict(validate=False))).hexdigest()

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ControlRequest":
        params = payload.get("params")
        if not isinstance(params, Mapping):
            raise ControlRequestError("control request params must be an object")
        schema_version = payload.get("schema_version")
        if not isinstance(schema_version, int) or isinstance(schema_version, bool):
            raise ControlRequestError("control request schema_version must be an integer")
        request = cls(
            schema_version=schema_version,
            request_id=str(payload.get("request_id", "")),
            instance_id=str(payload.get("instance_id", "")),
            session_id=str(payload.get("session_id", "")),
            action=str(payload.get("action", "")),
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
