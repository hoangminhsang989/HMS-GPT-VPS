from __future__ import annotations

import os

import pytest

from hms_gpt_vps.agent_windows_identity import (
    AGENT_SERVICE_ACCOUNT,
    LOCAL_SERVICE_SID,
    AgentWindowsIdentityError,
    AgentWindowsTokenSnapshot,
    NativeWindowsTokenInspector,
    probe_agent_service_identity,
    validate_agent_service_token,
)


class FakeInspector:
    def __init__(self, snapshot: AgentWindowsTokenSnapshot) -> None:
        self._snapshot = snapshot
        self.calls = 0

    def snapshot(self) -> AgentWindowsTokenSnapshot:
        self.calls += 1
        return self._snapshot


def good_snapshot() -> AgentWindowsTokenSnapshot:
    return AgentWindowsTokenSnapshot(
        user_sid=LOCAL_SERVICE_SID,
        service_sid_member=True,
        administrators_member=False,
        elevated=False,
    )


def test_valid_native_snapshot_is_the_only_source_of_runtime_identity() -> None:
    inspector = FakeInspector(good_snapshot())

    identity = probe_agent_service_identity(inspector=inspector)

    assert inspector.calls == 1
    assert identity.service_identity == AGENT_SERVICE_ACCOUNT
    assert identity.privilege == "non-admin"


@pytest.mark.parametrize(
    ("snapshot", "message"),
    [
        (
            AgentWindowsTokenSnapshot(
                user_sid="S-1-5-18",
                service_sid_member=True,
                administrators_member=False,
                elevated=False,
            ),
            "not LocalService",
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_member=False,
                administrators_member=False,
                elevated=False,
            ),
            "per-service SID",
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_member=True,
                administrators_member=True,
                elevated=False,
            ),
            "Administrators",
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_member=True,
                administrators_member=False,
                elevated=True,
            ),
            "elevated",
        ),
    ],
)
def test_identity_proof_fails_closed_when_any_token_fact_is_wrong(
    snapshot: AgentWindowsTokenSnapshot,
    message: str,
) -> None:
    with pytest.raises(PermissionError, match=message):
        validate_agent_service_token(snapshot)


def test_snapshot_shape_rejects_empty_sid_and_non_boolean_facts() -> None:
    with pytest.raises(AgentWindowsIdentityError, match="empty"):
        AgentWindowsTokenSnapshot(
            user_sid="",
            service_sid_member=True,
            administrators_member=False,
            elevated=False,
        ).validate_shape()

    with pytest.raises(AgentWindowsIdentityError, match="must be boolean"):
        AgentWindowsTokenSnapshot(
            user_sid=LOCAL_SERVICE_SID,
            service_sid_member=1,  # type: ignore[arg-type]
            administrators_member=False,
            elevated=False,
        ).validate_shape()


@pytest.mark.skipif(os.name == "nt", reason="non-Windows guard only")
def test_native_inspector_refuses_non_windows_hosts() -> None:
    with pytest.raises(OSError, match="requires Windows"):
        NativeWindowsTokenInspector()
