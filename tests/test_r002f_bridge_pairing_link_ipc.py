from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from hms_gpt_vps.bridge_pairing_link_ipc import (
    BridgePairingLinkIpcError,
    BridgePairingLinkIpcProtocolError,
    PairingLinkIpcDispatcher,
    PairingLinkIpcResult,
    _PIPE_NOWAIT,
    _PIPE_REJECT_REMOTE_CLIENTS,
    _PIPE_TYPE_MESSAGE,
    _parse_client_response,
    build_pairing_link_pipe_sddl,
    prove_hms_bridge_pairing_client_identity,
    request_pairing_link_from_running_hms_bridge,
)
from hms_gpt_vps.pairing_readiness_runtime import PairingIssueResult


_SERVICE_SID = "S-1-5-80-1-2-3-4-5"
_NONCE = "abcdefghijklmnopqrstuvwx"


class _Readiness:
    def __init__(self) -> None:
        self.calls = 0

    def issue(self) -> PairingIssueResult:
        self.calls += 1
        return PairingIssueResult(
            pair_id="pair-1",
            expires_at=datetime(2026, 8, 26, 1, 2, 3, tzinfo=timezone.utc),
            pairing_link="https://bridge.example.test/pair/pair-1#token=abc_DEF-123",
        )


def _request_bytes(nonce: str = _NONCE) -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "operation": "issue_pairing_link",
            "nonce": nonce,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _identity(pid: int = 321) -> dict[str, object]:
    return {
        "elevated_administrator": True,
        "process_sid": "S-1-5-21-1-2-3-1001",
        "identity_name": r"HOST\Admin",
        "service_name": "HMSBridge",
        "service_start_name": r"NT SERVICE\HMSBridge",
        "service_start_mode": "Manual",
        "service_state": "Running",
        "service_process_id": pid,
        "service_sid": _SERVICE_SID,
    }


def test_dispatcher_issues_exact_one_time_link_and_hides_it_from_repr() -> None:
    readiness = _Readiness()
    raw = PairingLinkIpcDispatcher(readiness).handle(_request_bytes())
    result = _parse_client_response(raw, _NONCE)
    assert readiness.calls == 1
    assert result.pair_id == "pair-1"
    assert result.expires_at == "2026-08-26T01:02:03Z"
    assert result.pairing_link.endswith("#token=abc_DEF-123")
    assert "abc_DEF-123" not in repr(result)
    assert "pairing_link" not in repr(result)


def test_malformed_request_is_protocol_scoped_and_never_issues() -> None:
    readiness = _Readiness()
    duplicate = (
        b'{"schema_version":1,"schema_version":1,'
        b'"operation":"issue_pairing_link","nonce":"abcdefghijklmnopqrstuvwx"}'
    )
    with pytest.raises(BridgePairingLinkIpcProtocolError):
        PairingLinkIpcDispatcher(readiness).handle(duplicate)
    assert readiness.calls == 0


def test_issuer_failure_returns_bounded_response_without_exception_text() -> None:
    class Broken:
        def issue(self):
            raise RuntimeError("SECRET-DO-NOT-LEAK")

    raw = PairingLinkIpcDispatcher(Broken()).handle(_request_bytes())
    text = raw.decode("utf-8")
    assert "SECRET-DO-NOT-LEAK" not in text
    assert json.loads(text) == {
        "schema_version": 1,
        "ok": False,
        "nonce": _NONCE,
        "error": "pairing_unavailable",
    }


def test_pairing_link_response_binds_pair_id_and_rejects_query() -> None:
    bad_pair = json.dumps(
        {
            "schema_version": 1,
            "ok": True,
            "nonce": _NONCE,
            "pair_id": "pair-2",
            "expires_at": "2026-08-26T01:02:03Z",
            "pairing_link": "https://bridge.example.test/pair/pair-1#token=abc",
        },
        separators=(",", ":"),
    ).encode()
    with pytest.raises(BridgePairingLinkIpcError, match="pair_id differs"):
        _parse_client_response(bad_pair, _NONCE)


def test_pipe_authority_is_protected_local_service_and_admin_only() -> None:
    sddl = build_pairing_link_pipe_sddl(_SERVICE_SID)
    assert sddl == (
        "D:P(A;;GA;;;SY)(A;;GRGW;;;BA)"
        "(A;;GA;;;S-1-5-80-1-2-3-4-5)"
    )
    assert ";;;WD)" not in sddl
    assert ";;;AN)" not in sddl
    assert _PIPE_TYPE_MESSAGE == 0x4
    assert _PIPE_NOWAIT == 0x1
    assert _PIPE_REJECT_REMOTE_CLIENTS == 0x8


def test_client_identity_requires_elevated_manual_running_service() -> None:
    def runner(script, timeout_seconds):
        assert "Win32_Service" in script
        assert timeout_seconds == 30
        return _identity()

    evidence = prove_hms_bridge_pairing_client_identity(runner=runner)
    assert evidence["service_process_id"] == 321

    stopped = _identity()
    stopped["service_state"] = "Stopped"
    with pytest.raises(BridgePairingLinkIpcError, match="Manual/Running"):
        prove_hms_bridge_pairing_client_identity(
            runner=lambda script, timeout_seconds: stopped
        )


def test_host_client_pins_same_scm_pid_before_and_after_request() -> None:
    evidence = _identity(777)
    observed: list[int] = []

    def request_fn(pid: int) -> PairingLinkIpcResult:
        observed.append(pid)
        return PairingLinkIpcResult(
            "pair-1",
            "2026-08-26T01:02:03Z",
            "https://bridge.example.test/pair/pair-1#token=abc",
        )

    result = request_pairing_link_from_running_hms_bridge(
        identity_runner=lambda script, timeout_seconds: dict(evidence),
        request_fn=request_fn,
    )
    assert result.pair_id == "pair-1"
    assert observed == [777]


def test_host_client_rejects_scm_pid_change_across_retrieval() -> None:
    snapshots = iter((_identity(777), _identity(778)))
    with pytest.raises(BridgePairingLinkIpcError, match="authority changed"):
        request_pairing_link_from_running_hms_bridge(
            identity_runner=lambda script, timeout_seconds: next(snapshots),
            request_fn=lambda pid: PairingLinkIpcResult(
                "pair-1",
                "2026-08-26T01:02:03Z",
                "https://bridge.example.test/pair/pair-1#token=abc",
            ),
        )
