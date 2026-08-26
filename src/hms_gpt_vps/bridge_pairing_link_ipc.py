from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import ctypes
from ctypes import wintypes
import json
import os
import secrets
import threading
import time
from typing import Callable, Protocol
from urllib.parse import parse_qs, unquote, urlsplit

from .bridge_service_identity import (
    HMS_BRIDGE_SERVICE_ACCOUNT,
    HMS_BRIDGE_SERVICE_NAME,
    require_hms_bridge_service_sid,
)
from .pairing_readiness_runtime import PairingIssueResult, PairingReadinessRuntime
from .powershell import ps_literal, run_powershell_json

PAIRING_LINK_IPC_SCHEMA_VERSION = 1
PAIRING_LINK_PIPE_NAME = r"\\.\pipe\HMS-GPT-VPS-Pairing"
PAIRING_LINK_OPERATION = "issue_pairing_link"
_MAX_MESSAGE_BYTES = 64 * 1024
_MAX_PAIRING_LINK_BYTES = 8 * 1024
_REQUEST_WAIT_SECONDS = 5.0
_PIPE_POLL_SECONDS = 0.02
_PIPE_ACCESS_DUPLEX = 0x00000003
_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_PIPE_TYPE_MESSAGE = 0x00000004
_PIPE_READMODE_MESSAGE = 0x00000002
_PIPE_NOWAIT = 0x00000001
_PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_ERROR_BROKEN_PIPE = 109
_ERROR_NO_DATA = 232
_ERROR_MORE_DATA = 234
_ERROR_PIPE_CONNECTED = 535
_ERROR_PIPE_LISTENING = 536
_SDDL_REVISION_1 = 1
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
_SAFE_NONCE = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
_CLIENT_EVIDENCE_KEYS = frozenset({
    "elevated_administrator", "process_sid", "identity_name", "service_name",
    "service_start_name", "service_start_mode", "service_state",
    "service_process_id", "service_sid",
})

class BridgePairingLinkIpcError(RuntimeError):
    pass

class BridgePairingLinkIpcUnavailableError(BridgePairingLinkIpcError):
    pass

class BridgePairingLinkIpcProtocolError(BridgePairingLinkIpcError):
    pass

class _PairingIssuer(Protocol):
    def issue(self) -> PairingIssueResult: ...

@dataclass(frozen=True)
class PairingLinkIpcResult:
    pair_id: str
    expires_at: str
    pairing_link: str = field(repr=False)

    def to_dict(self) -> dict[str, str]:
        return {"pair_id": self.pair_id, "expires_at": self.expires_at, "pairing_link": self.pairing_link}

def _validate_nonce(value: object) -> str:
    if (not isinstance(value, str) or not 20 <= len(value) <= 128
            or any(char not in _SAFE_NONCE for char in value)):
        raise BridgePairingLinkIpcError("pairing IPC nonce is invalid")
    return value

def _strict_json_object(data: bytes) -> dict[str, object]:
    if not isinstance(data, bytes) or not data or len(data) > _MAX_MESSAGE_BYTES:
        raise BridgePairingLinkIpcError("pairing IPC message size is invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgePairingLinkIpcError("pairing IPC message must be UTF-8") from exc
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise BridgePairingLinkIpcError("pairing IPC message contains duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except json.JSONDecodeError as exc:
        raise BridgePairingLinkIpcError("pairing IPC message is invalid JSON") from exc
    if not isinstance(value, dict):
        raise BridgePairingLinkIpcError("pairing IPC message must be a JSON object")
    return value

def _canonical_json_bytes(value: dict[str, object]) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BridgePairingLinkIpcError("pairing IPC response is not JSON-safe") from exc
    if not encoded or len(encoded) > _MAX_MESSAGE_BYTES:
        raise BridgePairingLinkIpcError("pairing IPC response size is invalid")
    return encoded

def _validate_pairing_link(
    value: object,
    *,
    expected_pair_id: str | None = None,
) -> str:
    if not isinstance(value, str) or not value:
        raise BridgePairingLinkIpcError("pairing IPC link is missing")
    if len(value.encode("utf-8")) > _MAX_PAIRING_LINK_BYTES:
        raise BridgePairingLinkIpcError("pairing IPC link exceeds size bound")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise BridgePairingLinkIpcError("pairing IPC link contains control characters")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
    ):
        raise BridgePairingLinkIpcError("pairing IPC link must be canonical HTTPS")
    if expected_pair_id is not None:
        if (
            not isinstance(expected_pair_id, str)
            or not expected_pair_id
            or "/pair/" not in parsed.path
            or unquote(parsed.path.rsplit("/", 1)[-1]) != expected_pair_id
        ):
            raise BridgePairingLinkIpcError(
                "pairing IPC link pair_id differs from response authority"
            )
    try:
        fragment = parse_qs(parsed.fragment, keep_blank_values=True, strict_parsing=True)
    except ValueError as exc:
        raise BridgePairingLinkIpcError("pairing IPC link fragment is invalid") from exc
    token_values = fragment.get("token")
    if (
        set(fragment) != {"token"}
        or not token_values
        or len(token_values) != 1
        or not token_values[0]
    ):
        raise BridgePairingLinkIpcError("pairing IPC link token fragment is invalid")
    return value

def build_pairing_link_pipe_sddl(expected_service_sid: str) -> str:
    service_sid = require_hms_bridge_service_sid(expected_service_sid)
    return "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)" + f"(A;;GA;;;{service_sid})"

def _parse_server_request(request_bytes: bytes) -> tuple[dict[str, object], str]:
    try:
        request = _strict_json_object(request_bytes)
        if frozenset(request) != {"schema_version", "operation", "nonce"}:
            raise BridgePairingLinkIpcError("pairing IPC request schema is invalid")
        schema = request["schema_version"]
        if (
            isinstance(schema, bool)
            or not isinstance(schema, int)
            or schema != PAIRING_LINK_IPC_SCHEMA_VERSION
        ):
            raise BridgePairingLinkIpcError("pairing IPC schema version is invalid")
        if request["operation"] != PAIRING_LINK_OPERATION:
            raise BridgePairingLinkIpcError("pairing IPC operation is unsupported")
        nonce = _validate_nonce(request["nonce"])
    except BridgePairingLinkIpcError as exc:
        raise BridgePairingLinkIpcProtocolError(
            "pairing IPC request failed protocol validation"
        ) from exc
    return request, nonce

class PairingLinkIpcDispatcher:
    def __init__(self, readiness: _PairingIssuer) -> None:
        if not callable(getattr(readiness, "issue", None)):
            raise TypeError("readiness must implement issue()")
        self.readiness = readiness

    def handle(self, request_bytes: bytes) -> bytes:
        _request, nonce = _parse_server_request(request_bytes)
        try:
            issued = self.readiness.issue()
        except Exception:
            return _canonical_json_bytes({
                "schema_version": PAIRING_LINK_IPC_SCHEMA_VERSION,
                "ok": False, "nonce": nonce, "error": "pairing_unavailable",
            })
        if not isinstance(issued, PairingIssueResult):
            raise BridgePairingLinkIpcError("pairing issuer returned an invalid result")
        if not isinstance(issued.pair_id, str) or not issued.pair_id:
            raise BridgePairingLinkIpcError("pairing issuer pair_id is invalid")
        if not isinstance(issued.expires_at, datetime) or issued.expires_at.tzinfo is None or issued.expires_at.utcoffset() is None:
            raise BridgePairingLinkIpcError("pairing issuer expiry is invalid")
        return _canonical_json_bytes({
            "schema_version": PAIRING_LINK_IPC_SCHEMA_VERSION,
            "ok": True, "nonce": nonce, "pair_id": issued.pair_id,
            "expires_at": issued.expires_at.isoformat().replace("+00:00", "Z"),
            "pairing_link": _validate_pairing_link(issued.pairing_link, expected_pair_id=issued.pair_id),
        })

def _parse_client_response(data: bytes, expected_nonce: str) -> PairingLinkIpcResult:
    nonce = _validate_nonce(expected_nonce)
    response = _strict_json_object(data)
    if response.get("schema_version") != PAIRING_LINK_IPC_SCHEMA_VERSION or response.get("nonce") != nonce:
        raise BridgePairingLinkIpcError("pairing IPC response authority mismatch")
    if response.get("ok") is False:
        if frozenset(response) != {"schema_version", "ok", "nonce", "error"} or response.get("error") != "pairing_unavailable":
            raise BridgePairingLinkIpcError("pairing IPC error response schema is invalid")
        raise BridgePairingLinkIpcUnavailableError("HMSBridge pairing link is unavailable")
    expected = {"schema_version", "ok", "nonce", "pair_id", "expires_at", "pairing_link"}
    if response.get("ok") is not True or frozenset(response) != expected:
        raise BridgePairingLinkIpcError("pairing IPC success response schema is invalid")
    pair_id, expires_at = response.get("pair_id"), response.get("expires_at")
    if not isinstance(pair_id, str) or not pair_id or not isinstance(expires_at, str) or not expires_at:
        raise BridgePairingLinkIpcError("pairing IPC success response fields are invalid")
    try:
        parsed = datetime.fromisoformat(expires_at[:-1] + "+00:00" if expires_at.endswith("Z") else expires_at)
    except ValueError as exc:
        raise BridgePairingLinkIpcError("pairing IPC response expiry is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise BridgePairingLinkIpcError("pairing IPC response expiry must be timezone-aware")
    return PairingLinkIpcResult(
        pair_id,
        expires_at,
        _validate_pairing_link(
            response.get("pairing_link"),
            expected_pair_id=pair_id,
        ),
    )

def build_hms_bridge_pairing_client_identity_script() -> str:
    service_name = ps_literal(HMS_BRIDGE_SERVICE_NAME)
    service_account = ps_literal(HMS_BRIDGE_SERVICE_ACCOUNT)
    return f"""
$ErrorActionPreference = 'Stop'
$serviceName = {service_name}
$serviceAccount = {service_account}
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {{ throw 'Pairing client process token has no user SID' }}
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$rows = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop)
if ($rows.Count -ne 1) {{ throw 'Expected exactly one HMSBridge service' }}
$service = $rows[0]
$serviceSid = ([System.Security.Principal.NTAccount]::new($serviceAccount)).Translate(
  [System.Security.Principal.SecurityIdentifier]
).Value
[pscustomobject]@{{
  elevated_administrator = [bool]$elevated
  process_sid = [string]$identity.User.Value
  identity_name = [string]$identity.Name
  service_name = [string]$service.Name
  service_start_name = [string]$service.StartName
  service_start_mode = [string]$service.StartMode
  service_state = [string]$service.State
  service_process_id = [int]$service.ProcessId
  service_sid = [string]$serviceSid
}}
""".strip()

def prove_hms_bridge_pairing_client_identity(
    *, runner: Callable[..., dict[str, object]] | None = None,
) -> dict[str, object]:
    execute = run_powershell_json if runner is None else runner
    result = execute(build_hms_bridge_pairing_client_identity_script(), timeout_seconds=30)
    if frozenset(result) != _CLIENT_EVIDENCE_KEYS:
        raise BridgePairingLinkIpcError("pairing client identity evidence schema is invalid")
    if result.get("elevated_administrator") is not True:
        raise BridgePairingLinkIpcError("pairing-link retrieval requires elevated Administrator")
    process_sid, identity_name = result.get("process_sid"), result.get("identity_name")
    if (not isinstance(process_sid, str) or not process_sid or process_sid.startswith("S-1-5-80-")
            or not isinstance(identity_name, str) or not identity_name
            or identity_name.casefold() == HMS_BRIDGE_SERVICE_ACCOUNT.casefold()):
        raise BridgePairingLinkIpcError("pairing client process identity is invalid")
    if result.get("service_name") != HMS_BRIDGE_SERVICE_NAME:
        raise BridgePairingLinkIpcError("pairing client observed the wrong service name")
    start_name = result.get("service_start_name")
    if not isinstance(start_name, str) or start_name.casefold() != HMS_BRIDGE_SERVICE_ACCOUNT.casefold():
        raise BridgePairingLinkIpcError("pairing client observed the wrong service account")
    if result.get("service_start_mode") != "Manual" or result.get("service_state") != "Running":
        raise BridgePairingLinkIpcError("HMSBridge must be exact Manual/Running for pairing-link retrieval")
    pid = result.get("service_process_id")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise BridgePairingLinkIpcError("HMSBridge running process id is invalid")
    require_hms_bridge_service_sid(result.get("service_sid"))
    return dict(result)

class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    ]

class _NativePipeApi:
    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("HMSBridge pairing named pipe requires Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        self._configure()

    @staticmethod
    def _error(message: str) -> OSError:
        code = ctypes.get_last_error()
        return OSError(code, f"{message} (WinError {code})")

    def _configure(self) -> None:
        k32, adv = self.kernel32, self.advapi32
        k32.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(_SECURITY_ATTRIBUTES)]
        k32.CreateNamedPipeW.restype = wintypes.HANDLE
        k32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        k32.ConnectNamedPipe.restype = wintypes.BOOL
        k32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
        k32.DisconnectNamedPipe.restype = wintypes.BOOL
        k32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
                                 ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        k32.ReadFile.restype = wintypes.BOOL
        k32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
                                  ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        k32.WriteFile.restype = wintypes.BOOL
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        k32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        k32.WaitNamedPipeW.restype = wintypes.BOOL
        k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                    wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.SetNamedPipeHandleState.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                                                wintypes.LPVOID, wintypes.LPVOID]
        k32.SetNamedPipeHandleState.restype = wintypes.BOOL
        k32.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
        k32.GetNamedPipeServerProcessId.restype = wintypes.BOOL
        k32.LocalFree.argtypes = [wintypes.HLOCAL]
        k32.LocalFree.restype = wintypes.HLOCAL
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID),
            ctypes.POINTER(wintypes.DWORD)]
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

    def create_server_pipe(self, sddl: str):
        descriptor = wintypes.LPVOID()
        if not self.advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ctypes.byref(descriptor), None
        ):
            raise self._error("ConvertStringSecurityDescriptorToSecurityDescriptorW failed")
        attributes = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), descriptor, False)
        try:
            handle = self.kernel32.CreateNamedPipeW(
                PAIRING_LINK_PIPE_NAME,
                _PIPE_ACCESS_DUPLEX | _FILE_FLAG_FIRST_PIPE_INSTANCE,
                _PIPE_TYPE_MESSAGE | _PIPE_READMODE_MESSAGE | _PIPE_NOWAIT | _PIPE_REJECT_REMOTE_CLIENTS,
                1, _MAX_MESSAGE_BYTES, _MAX_MESSAGE_BYTES, 0, ctypes.byref(attributes),
            )
            if handle == _INVALID_HANDLE_VALUE:
                raise self._error("CreateNamedPipeW failed")
            return handle
        finally:
            self.kernel32.LocalFree(descriptor)

    def close(self, handle) -> None:
        if handle not in (None, _INVALID_HANDLE_VALUE):
            self.kernel32.CloseHandle(handle)

@dataclass
class BridgePairingLinkIpcServer:
    readiness: _PairingIssuer
    expected_service_sid: str
    fatal_stop: threading.Event
    api: _NativePipeApi | None = None
    _thread: threading.Thread | None = field(init=False, default=None, repr=False)
    _stop: threading.Event = field(init=False, default_factory=threading.Event, repr=False)
    _errors: list[BaseException] = field(init=False, default_factory=list, repr=False)
    _ready: threading.Event = field(init=False, default_factory=threading.Event, repr=False)

    def __post_init__(self) -> None:
        if not callable(getattr(self.readiness, "issue", None)):
            raise TypeError("readiness must implement issue()")
        self.expected_service_sid = require_hms_bridge_service_sid(self.expected_service_sid)
        if not isinstance(self.fatal_stop, threading.Event):
            raise TypeError("fatal_stop must be a threading.Event")

    @property
    def ready(self) -> bool:
        return (
            self._ready.is_set()
            and self._thread is not None
            and self._thread.is_alive()
            and not self._errors
            and not self._stop.is_set()
        )

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def error(self) -> BaseException | None:
        return self._errors[0] if self._errors else None

    def start(self) -> None:
        if self._thread is not None or self._ready.is_set():
            raise BridgePairingLinkIpcError("pairing IPC server is already started")
        api = self.api or _NativePipeApi()
        self.api = api
        handle = api.create_server_pipe(build_pairing_link_pipe_sddl(self.expected_service_sid))
        dispatcher = PairingLinkIpcDispatcher(self.readiness)

        def serve() -> None:
            try:
                self._ready.set()
                self._serve(api, handle, dispatcher)
            except BaseException as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    self._errors.append(exc)
                    self.fatal_stop.set()
                    raise
                self._errors.append(exc)
                self.fatal_stop.set()
            finally:
                self._ready.clear()
                api.close(handle)

        thread = threading.Thread(
            target=serve,
            name="HMSBridgePairingPipe",
            daemon=False,
        )
        self._thread = thread
        try:
            thread.start()
        except Exception:
            self._thread = None
            api.close(handle)
            raise

        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            if self.error is not None:
                try:
                    self.shutdown()
                finally:
                    raise BridgePairingLinkIpcError(
                        "pairing IPC server failed during startup"
                    ) from self.error
            if self.ready:
                return
            time.sleep(_PIPE_POLL_SECONDS)
        try:
            self.shutdown()
        finally:
            raise BridgePairingLinkIpcError(
                "pairing IPC server did not report startup readiness"
            )

    def _serve(
        self,
        api: _NativePipeApi,
        handle,
        dispatcher: PairingLinkIpcDispatcher,
    ) -> None:
        while not self._stop.is_set():
            connected = api.kernel32.ConnectNamedPipe(handle, None)
            if not connected:
                code = ctypes.get_last_error()
                if code == _ERROR_PIPE_LISTENING:
                    self._stop.wait(_PIPE_POLL_SECONDS)
                    continue
                if code == _ERROR_PIPE_CONNECTED:
                    connected = True
                else:
                    raise OSError(code, f"ConnectNamedPipe failed (WinError {code})")
            if connected:
                try:
                    self._serve_one_client(api, handle, dispatcher)
                finally:
                    api.kernel32.DisconnectNamedPipe(handle)

    def _serve_one_client(
        self,
        api: _NativePipeApi,
        handle,
        dispatcher: PairingLinkIpcDispatcher,
    ) -> None:
        deadline = time.monotonic() + _REQUEST_WAIT_SECONDS
        request: bytes | None = None
        while not self._stop.is_set() and time.monotonic() < deadline:
            buffer = ctypes.create_string_buffer(_MAX_MESSAGE_BYTES)
            read = wintypes.DWORD()
            ok = api.kernel32.ReadFile(
                handle,
                buffer,
                _MAX_MESSAGE_BYTES,
                ctypes.byref(read),
                None,
            )
            if ok:
                size = int(read.value)
                if size <= 0:
                    self._stop.wait(_PIPE_POLL_SECONDS)
                    continue
                request = bytes(buffer.raw[:size])
                break
            code = ctypes.get_last_error()
            if code in {_ERROR_NO_DATA, _ERROR_PIPE_LISTENING}:
                self._stop.wait(_PIPE_POLL_SECONDS)
                continue
            if code == _ERROR_BROKEN_PIPE:
                return
            if code == _ERROR_MORE_DATA:
                raise BridgePairingLinkIpcError(
                    "pairing IPC request exceeds message size bound"
                )
            raise OSError(code, f"ReadFile failed (WinError {code})")

        if request is None:
            return

        try:
            response = dispatcher.handle(request)
        except BridgePairingLinkIpcProtocolError:
            return

        written = wintypes.DWORD()
        output = ctypes.create_string_buffer(response)
        if not api.kernel32.WriteFile(
            handle,
            output,
            len(response),
            ctypes.byref(written),
            None,
        ):
            code = ctypes.get_last_error()
            if code == _ERROR_BROKEN_PIPE:
                return
            raise OSError(code, f"WriteFile failed (WinError {code})")
        if int(written.value) != len(response):
            raise BridgePairingLinkIpcError(
                "pairing IPC response write was incomplete"
            )

    def shutdown(self) -> None:
        thread = self._thread
        if thread is None:
            return
        self._stop.set()
        thread.join(timeout=6.0)
        if thread.is_alive():
            raise BridgePairingLinkIpcError(
                "pairing IPC server did not stop within bounded shutdown"
            )
        self._thread = None
        self._ready.clear()


def start_pairing_link_ipc_server(
    readiness: PairingReadinessRuntime,
    expected_service_sid: str,
    fatal_stop: threading.Event,
) -> BridgePairingLinkIpcServer:
    if not isinstance(readiness, PairingReadinessRuntime):
        raise TypeError("readiness must be PairingReadinessRuntime")
    server = BridgePairingLinkIpcServer(
        readiness=readiness,
        expected_service_sid=expected_service_sid,
        fatal_stop=fatal_stop,
    )
    server.start()
    return server


def _native_request_pairing_link(
    expected_server_pid: int,
    *,
    timeout_seconds: float = 10.0,
    api: _NativePipeApi | None = None,
) -> PairingLinkIpcResult:
    if (
        isinstance(expected_server_pid, bool)
        or not isinstance(expected_server_pid, int)
        or expected_server_pid <= 0
    ):
        raise ValueError("expected_server_pid must be a positive integer")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 1.0 <= float(timeout_seconds) <= 60.0
    ):
        raise ValueError("timeout_seconds must be between 1 and 60")
    native = api or _NativePipeApi()
    deadline = time.monotonic() + float(timeout_seconds)
    remaining_ms = max(1, int(float(timeout_seconds) * 1000))
    if not native.kernel32.WaitNamedPipeW(PAIRING_LINK_PIPE_NAME, remaining_ms):
        raise BridgePairingLinkIpcUnavailableError(
            "HMSBridge pairing IPC is unavailable"
        )

    handle = native.kernel32.CreateFileW(
        PAIRING_LINK_PIPE_NAME,
        _GENERIC_READ | _GENERIC_WRITE,
        0,
        None,
        _OPEN_EXISTING,
        0,
        None,
    )
    if handle == _INVALID_HANDLE_VALUE:
        raise native._error("CreateFileW for pairing IPC failed")
    try:
        mode = wintypes.DWORD(_PIPE_READMODE_MESSAGE | _PIPE_NOWAIT)
        if not native.kernel32.SetNamedPipeHandleState(
            handle, ctypes.byref(mode), None, None
        ):
            raise native._error("SetNamedPipeHandleState failed")

        server_pid = wintypes.ULONG()
        if not native.kernel32.GetNamedPipeServerProcessId(
            handle, ctypes.byref(server_pid)
        ):
            raise native._error("GetNamedPipeServerProcessId failed")
        if int(server_pid.value) != expected_server_pid:
            raise BridgePairingLinkIpcError(
                "pairing IPC server PID differs from SCM authority"
            )

        nonce = secrets.token_urlsafe(18)
        _validate_nonce(nonce)
        request = _canonical_json_bytes(
            {
                "schema_version": PAIRING_LINK_IPC_SCHEMA_VERSION,
                "operation": PAIRING_LINK_OPERATION,
                "nonce": nonce,
            }
        )
        request_buffer = ctypes.create_string_buffer(request)
        written = wintypes.DWORD()
        if not native.kernel32.WriteFile(
            handle,
            request_buffer,
            len(request),
            ctypes.byref(written),
            None,
        ):
            raise native._error("WriteFile pairing IPC request failed")
        if int(written.value) != len(request):
            raise BridgePairingLinkIpcError(
                "pairing IPC request write was incomplete"
            )

        while time.monotonic() < deadline:
            buffer = ctypes.create_string_buffer(_MAX_MESSAGE_BYTES)
            read = wintypes.DWORD()
            ok = native.kernel32.ReadFile(
                handle,
                buffer,
                _MAX_MESSAGE_BYTES,
                ctypes.byref(read),
                None,
            )
            if ok:
                size = int(read.value)
                if size <= 0:
                    time.sleep(_PIPE_POLL_SECONDS)
                    continue
                return _parse_client_response(bytes(buffer.raw[:size]), nonce)
            code = ctypes.get_last_error()
            if code in {_ERROR_NO_DATA, _ERROR_PIPE_LISTENING}:
                time.sleep(_PIPE_POLL_SECONDS)
                continue
            if code == _ERROR_MORE_DATA:
                raise BridgePairingLinkIpcError(
                    "pairing IPC response exceeds message size bound"
                )
            if code == _ERROR_BROKEN_PIPE:
                raise BridgePairingLinkIpcUnavailableError(
                    "HMSBridge pairing IPC closed before response"
                )
            raise OSError(code, f"ReadFile pairing IPC response failed (WinError {code})")
        raise BridgePairingLinkIpcUnavailableError(
            "HMSBridge pairing IPC timed out"
        )
    finally:
        native.close(handle)


PairingClientIdentityRunner = Callable[..., dict[str, object]]
PairingRequestFn = Callable[[int], PairingLinkIpcResult]


def request_pairing_link_from_running_hms_bridge(
    *,
    identity_runner: PairingClientIdentityRunner | None = None,
    request_fn: PairingRequestFn | None = None,
) -> PairingLinkIpcResult:
    pre = prove_hms_bridge_pairing_client_identity(runner=identity_runner)
    pid = pre["service_process_id"]
    assert isinstance(pid, int) and not isinstance(pid, bool)
    execute = (
        (lambda expected_pid: _native_request_pairing_link(expected_pid))
        if request_fn is None
        else request_fn
    )
    result = execute(pid)
    if not isinstance(result, PairingLinkIpcResult):
        raise BridgePairingLinkIpcError(
            "pairing IPC client returned an invalid result"
        )
    post = prove_hms_bridge_pairing_client_identity(runner=identity_runner)
    if (
        post.get("service_process_id") != pid
        or post.get("service_sid") != pre.get("service_sid")
        or post.get("service_state") != "Running"
        or post.get("service_start_mode") != "Manual"
    ):
        raise BridgePairingLinkIpcError(
            "HMSBridge SCM authority changed across pairing-link retrieval"
        )
    return result
