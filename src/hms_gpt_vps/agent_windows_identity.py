from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import os
from typing import Protocol

from .agent_guest_runtime import AgentRuntimeIdentity


LOCAL_SERVICE_SID = "S-1-5-19"
BUILTIN_ADMINISTRATORS_SID = "S-1-5-32-544"
AGENT_SERVICE_ACCOUNT = r"NT SERVICE\HMSAgent"

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_TOKEN_GROUPS = 2
_TOKEN_ELEVATION = 20
_ERROR_INSUFFICIENT_BUFFER = 122
_MAX_TOKEN_GROUPS = 4096


class AgentWindowsIdentityError(RuntimeError):
    pass


@dataclass(frozen=True)
class AgentWindowsTokenSnapshot:
    user_sid: str
    service_sid_present: bool
    administrators_sid_present: bool
    elevated: bool

    def validate_shape(self) -> None:
        if not self.user_sid.strip():
            raise AgentWindowsIdentityError("Windows token user SID is empty")
        if not self.user_sid.upper().startswith("S-"):
            raise AgentWindowsIdentityError("Windows token user SID is malformed")
        for name, value in (
            ("service_sid_present", self.service_sid_present),
            ("administrators_sid_present", self.administrators_sid_present),
            ("elevated", self.elevated),
        ):
            if not isinstance(value, bool):
                raise AgentWindowsIdentityError(f"{name} must be boolean")


class AgentWindowsTokenInspector(Protocol):
    def snapshot(self) -> AgentWindowsTokenSnapshot: ...


def validate_agent_service_token(
    snapshot: AgentWindowsTokenSnapshot,
) -> AgentRuntimeIdentity:
    """Convert native Windows token facts into the runtime identity contract.

    The service process must simultaneously prove all of the following:
    - its primary user is LocalService (S-1-5-19),
    - the per-service SID `NT SERVICE\\HMSAgent` is present in TokenGroups,
    - the Builtin Administrators SID is absent from TokenGroups,
    - the token is not elevated.

    Presence is read directly with GetTokenInformation(TokenGroups). This avoids
    treating `CheckTokenMembership` as a primary-token enumeration API and also
    lets this proof reject an Administrators SID even if Windows marked it
    deny-only or disabled. No value from config, environment, command line, or
    the health document can substitute for these operating-system token facts.
    """
    snapshot.validate_shape()
    if snapshot.user_sid.upper() != LOCAL_SERVICE_SID:
        raise PermissionError("HMS Agent process token is not LocalService")
    if not snapshot.service_sid_present:
        raise PermissionError("HMS Agent per-service SID is absent from process token")
    if snapshot.administrators_sid_present:
        raise PermissionError("HMS Agent process token contains Administrators SID")
    if snapshot.elevated:
        raise PermissionError("HMS Agent process token is elevated")

    identity = AgentRuntimeIdentity(
        service_identity=AGENT_SERVICE_ACCOUNT,
        privilege="non-admin",
    )
    identity.validate()
    return identity


def probe_agent_service_identity(
    *,
    inspector: AgentWindowsTokenInspector | None = None,
) -> AgentRuntimeIdentity:
    checked = inspector or NativeWindowsTokenInspector()
    return validate_agent_service_token(checked.snapshot())


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


class _TOKEN_USER_VALUE(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


class _TOKEN_GROUPS_LAYOUT(ctypes.Structure):
    _fields_ = [
        ("GroupCount", wintypes.DWORD),
        ("Groups", _SID_AND_ATTRIBUTES * 1),
    ]


class _TOKEN_ELEVATION_VALUE(ctypes.Structure):
    _fields_ = [("TokenIsElevated", wintypes.DWORD)]


def _last_error(message: str) -> AgentWindowsIdentityError:
    code = ctypes.get_last_error()
    return AgentWindowsIdentityError(f"{message} (WinError {code})")


class NativeWindowsTokenInspector:
    """Read current-process identity directly through Win32 token APIs."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("native Windows Agent identity proof requires Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._configure_prototypes()

    def _configure_prototypes(self) -> None:
        self._kernel32.GetCurrentProcess.argtypes = []
        self._kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
        self._kernel32.LocalFree.restype = wintypes.HLOCAL

        self._advapi32.OpenProcessToken.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        self._advapi32.OpenProcessToken.restype = wintypes.BOOL
        self._advapi32.GetTokenInformation.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._advapi32.GetTokenInformation.restype = wintypes.BOOL
        self._advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self._advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
        self._advapi32.ConvertStringSidToSidW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
        self._advapi32.LookupAccountNameW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._advapi32.LookupAccountNameW.restype = wintypes.BOOL
        self._advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._advapi32.EqualSid.restype = wintypes.BOOL

    def _open_current_token(self) -> wintypes.HANDLE:
        token = wintypes.HANDLE()
        if not self._advapi32.OpenProcessToken(
            self._kernel32.GetCurrentProcess(),
            _TOKEN_QUERY,
            ctypes.byref(token),
        ):
            raise _last_error("OpenProcessToken failed")
        return token

    def _read_token_buffer(
        self,
        token: wintypes.HANDLE,
        information_class: int,
        label: str,
    ) -> ctypes.Array[ctypes.c_char]:
        needed = wintypes.DWORD(0)
        ctypes.set_last_error(0)
        ok = self._advapi32.GetTokenInformation(
            token,
            information_class,
            None,
            0,
            ctypes.byref(needed),
        )
        if ok or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise _last_error(f"GetTokenInformation({label}) sizing failed")
        if needed.value == 0:
            raise AgentWindowsIdentityError(f"{label} returned an empty buffer size")

        buffer = ctypes.create_string_buffer(needed.value)
        if not self._advapi32.GetTokenInformation(
            token,
            information_class,
            buffer,
            needed.value,
            ctypes.byref(needed),
        ):
            raise _last_error(f"GetTokenInformation({label}) failed")
        return buffer

    def _token_user_sid(self, token: wintypes.HANDLE) -> str:
        buffer = self._read_token_buffer(token, _TOKEN_USER, "TokenUser")
        token_user = ctypes.cast(
            buffer,
            ctypes.POINTER(_TOKEN_USER_VALUE),
        ).contents
        if not token_user.User.Sid:
            raise AgentWindowsIdentityError("TokenUser returned a null SID")
        return self._sid_to_string(token_user.User.Sid)

    def _token_groups_contain_sid(
        self,
        token: wintypes.HANDLE,
        target_sid: ctypes.c_void_p,
    ) -> bool:
        buffer = self._read_token_buffer(token, _TOKEN_GROUPS, "TokenGroups")
        buffer_size = ctypes.sizeof(buffer)
        groups_offset = _TOKEN_GROUPS_LAYOUT.Groups.offset
        if buffer_size < groups_offset:
            raise AgentWindowsIdentityError("TokenGroups buffer is shorter than header")

        group_count = ctypes.cast(
            buffer,
            ctypes.POINTER(wintypes.DWORD),
        ).contents.value
        if group_count > _MAX_TOKEN_GROUPS:
            raise AgentWindowsIdentityError("TokenGroups count exceeds safety bound")

        entry_size = ctypes.sizeof(_SID_AND_ATTRIBUTES)
        required_size = groups_offset + (group_count * entry_size)
        if required_size > buffer_size:
            raise AgentWindowsIdentityError("TokenGroups buffer is structurally truncated")

        base_address = ctypes.addressof(buffer) + groups_offset
        for index in range(group_count):
            entry = ctypes.cast(
                base_address + (index * entry_size),
                ctypes.POINTER(_SID_AND_ATTRIBUTES),
            ).contents
            if not entry.Sid:
                raise AgentWindowsIdentityError("TokenGroups contains a null SID")
            if self._advapi32.EqualSid(entry.Sid, target_sid):
                return True
        return False

    def _sid_to_string(self, sid: ctypes.c_void_p | int) -> str:
        sid_value = sid.value if isinstance(sid, ctypes.c_void_p) else sid
        if not sid_value:
            raise AgentWindowsIdentityError("cannot stringify a null SID")
        text = wintypes.LPWSTR()
        if not self._advapi32.ConvertSidToStringSidW(
            ctypes.c_void_p(sid_value),
            ctypes.byref(text),
        ):
            raise _last_error("ConvertSidToStringSidW failed")
        try:
            value = text.value
            if not value:
                raise AgentWindowsIdentityError("Windows returned an empty SID string")
            return value.upper()
        finally:
            if text:
                self._kernel32.LocalFree(ctypes.cast(text, wintypes.HLOCAL))

    def _token_is_elevated(self, token: wintypes.HANDLE) -> bool:
        elevation = _TOKEN_ELEVATION_VALUE()
        returned = wintypes.DWORD(0)
        if not self._advapi32.GetTokenInformation(
            token,
            _TOKEN_ELEVATION,
            ctypes.byref(elevation),
            ctypes.sizeof(elevation),
            ctypes.byref(returned),
        ):
            raise _last_error("GetTokenInformation(TokenElevation) failed")
        if returned.value < ctypes.sizeof(elevation):
            raise AgentWindowsIdentityError("TokenElevation returned a short buffer")
        return bool(elevation.TokenIsElevated)

    def _sid_from_string(self, value: str) -> ctypes.c_void_p:
        sid = ctypes.c_void_p()
        if not self._advapi32.ConvertStringSidToSidW(value, ctypes.byref(sid)):
            raise _last_error("ConvertStringSidToSidW failed")
        if not sid.value:
            raise AgentWindowsIdentityError("ConvertStringSidToSidW returned null")
        return sid

    def _lookup_account_sid(self, account: str) -> ctypes.Array[ctypes.c_char]:
        sid_size = wintypes.DWORD(0)
        domain_size = wintypes.DWORD(0)
        sid_use = wintypes.DWORD(0)
        ctypes.set_last_error(0)
        ok = self._advapi32.LookupAccountNameW(
            None,
            account,
            None,
            ctypes.byref(sid_size),
            None,
            ctypes.byref(domain_size),
            ctypes.byref(sid_use),
        )
        if ok or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise _last_error(f"LookupAccountNameW sizing failed for {account}")
        if sid_size.value == 0:
            raise AgentWindowsIdentityError(
                f"LookupAccountNameW returned an empty SID size for {account}"
            )

        sid_buffer = ctypes.create_string_buffer(sid_size.value)
        domain_buffer = ctypes.create_unicode_buffer(max(1, domain_size.value))
        if not self._advapi32.LookupAccountNameW(
            None,
            account,
            sid_buffer,
            ctypes.byref(sid_size),
            domain_buffer,
            ctypes.byref(domain_size),
            ctypes.byref(sid_use),
        ):
            raise _last_error(f"LookupAccountNameW failed for {account}")
        return sid_buffer

    def snapshot(self) -> AgentWindowsTokenSnapshot:
        token = self._open_current_token()
        admin_sid: ctypes.c_void_p | None = None
        try:
            user_sid = self._token_user_sid(token)

            service_sid_buffer = self._lookup_account_sid(AGENT_SERVICE_ACCOUNT)
            service_sid_present = self._token_groups_contain_sid(
                token,
                ctypes.cast(service_sid_buffer, ctypes.c_void_p),
            )

            admin_sid = self._sid_from_string(BUILTIN_ADMINISTRATORS_SID)
            administrators_sid_present = self._token_groups_contain_sid(
                token,
                admin_sid,
            )
            elevated = self._token_is_elevated(token)

            snapshot = AgentWindowsTokenSnapshot(
                user_sid=user_sid,
                service_sid_present=service_sid_present,
                administrators_sid_present=administrators_sid_present,
                elevated=elevated,
            )
            snapshot.validate_shape()
            return snapshot
        finally:
            if admin_sid is not None and admin_sid.value:
                self._kernel32.LocalFree(wintypes.HLOCAL(admin_sid.value))
            self._kernel32.CloseHandle(token)
