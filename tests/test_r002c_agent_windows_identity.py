from __future__ import annotations

import ctypes
import os

import pytest

from hms_gpt_vps.agent_windows_identity import (
    AGENT_SERVICE_ACCOUNT,
    BUILTIN_ADMINISTRATORS_SID,
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
        service_sid_present=True,
        administrators_sid_present=False,
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
                service_sid_present=True,
                administrators_sid_present=False,
                elevated=False,
            ),
            "not LocalService",
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_present=False,
                administrators_sid_present=False,
                elevated=False,
            ),
            "per-service SID",
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_present=True,
                administrators_sid_present=True,
                elevated=False,
            ),
            "Administrators",
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_present=True,
                administrators_sid_present=False,
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
            service_sid_present=True,
            administrators_sid_present=False,
            elevated=False,
        ).validate_shape()

    with pytest.raises(AgentWindowsIdentityError, match="must be boolean"):
        AgentWindowsTokenSnapshot(
            user_sid=LOCAL_SERVICE_SID,
            service_sid_present=1,  # type: ignore[arg-type]
            administrators_sid_present=False,
            elevated=False,
        ).validate_shape()


@pytest.mark.skipif(os.name == "nt", reason="non-Windows guard only")
def test_native_inspector_refuses_non_windows_hosts() -> None:
    with pytest.raises(OSError, match="requires Windows"):
        NativeWindowsTokenInspector()


@pytest.mark.skipif(os.name != "nt", reason="native Win32 proof smoke requires Windows")
def test_native_windows_token_ffi_smoke_uses_real_process_token() -> None:
    inspector = NativeWindowsTokenInspector()
    token = inspector._open_current_token()
    admin_sid = None
    try:
        user_sid = inspector._token_user_sid(token)
        assert user_sid.startswith("S-")

        local_service_buffer = inspector._lookup_account_sid(
            r"NT AUTHORITY\LOCAL SERVICE"
        )
        local_service_sid = inspector._sid_to_string(
            ctypes.cast(local_service_buffer, ctypes.c_void_p)
        )
        assert local_service_sid == LOCAL_SERVICE_SID

        admin_sid = inspector._sid_from_string(BUILTIN_ADMINISTRATORS_SID)
        assert isinstance(
            inspector._token_groups_contain_sid(token, admin_sid),
            bool,
        )
        assert isinstance(inspector._token_is_elevated(token), bool)
    finally:
        if admin_sid is not None and admin_sid.value:
            inspector._kernel32.LocalFree(admin_sid.value)
        inspector._kernel32.CloseHandle(token)
