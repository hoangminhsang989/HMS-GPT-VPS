from __future__ import annotations

import pytest

from hms_gpt_vps.control_request import (
    CONTROL_REQUEST_SCHEMA_VERSION,
    ControlRequest,
    ControlRequestError,
)


def payload(**overrides):
    value = {
        "schema_version": CONTROL_REQUEST_SCHEMA_VERSION,
        "request_id": "req-01",
        "instance_id": "hms-01",
        "session_id": "session-01",
        "action": "workspace.read",
        "params": {"path": "README.md"},
    }
    value.update(overrides)
    return value


def test_from_dict_preserves_exact_authority_without_string_coercion() -> None:
    request = ControlRequest.from_dict(payload())
    assert request.request_id == "req-01"
    assert request.instance_id == "hms-01"
    assert request.session_id == "session-01"
    assert request.action == "workspace.read"

    for field_name, bad_value in (
        ("request_id", 123),
        ("instance_id", 123),
        ("session_id", 123),
        ("action", 123),
    ):
        with pytest.raises(ControlRequestError):
            ControlRequest.from_dict(payload(**{field_name: bad_value}))


def test_boolean_schema_version_is_rejected_in_constructor_and_parser() -> None:
    direct = ControlRequest(
        schema_version=True,
        request_id="req-01",
        instance_id="hms-01",
        session_id="session-01",
        action="workspace.read",
        params={"path": "README.md"},
    )
    with pytest.raises(ControlRequestError, match="unsupported control request schema"):
        direct.validate()

    with pytest.raises(ControlRequestError, match="must be an integer"):
        ControlRequest.from_dict(payload(schema_version=True))


def test_from_dict_requires_exact_top_level_fields() -> None:
    missing = payload()
    del missing["action"]
    with pytest.raises(ControlRequestError, match="fields do not match schema"):
        ControlRequest.from_dict(missing)

    extra = payload(extra="not-authority")
    with pytest.raises(ControlRequestError, match="fields do not match schema"):
        ControlRequest.from_dict(extra)


def test_instance_id_rejects_whitespace_and_control_characters() -> None:
    for bad in (" hms-01", "hms-01 ", "hms\n01", ""):
        with pytest.raises(ControlRequestError):
            ControlRequest.from_dict(payload(instance_id=bad))


def test_valid_request_hash_remains_canonical() -> None:
    first = ControlRequest.from_dict(
        payload(params={"b": 2, "a": 1})
    )
    second = ControlRequest.from_dict(
        payload(params={"a": 1, "b": 2})
    )
    assert first.request_sha256() == second.request_sha256()
