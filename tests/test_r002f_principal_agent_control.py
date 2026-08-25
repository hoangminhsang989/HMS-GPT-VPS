from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3

import pytest

from hms_gpt_vps.agent_bridge_service import AgentBridgeService
from hms_gpt_vps.agent_command_exact_status import get_exact_agent_command_status
from hms_gpt_vps.agent_command_store import AgentCommandStore
from hms_gpt_vps.agent_connection_registry import AgentConnectionRegistry, AgentPresence
from hms_gpt_vps.agent_transport_protocol import (
    AGENT_TRANSPORT_SCHEMA_VERSION,
    AgentCommandResult,
    AgentDeviceCredential,
)
from hms_gpt_vps.control_gateway import ControlGateway
from hms_gpt_vps.control_request import (
    CONTROL_REQUEST_SCHEMA_VERSION,
    ControlRequest,
)
from hms_gpt_vps.control_session_store import ControlSessionStore
from hms_gpt_vps.idempotency_store import IdempotencyStore
from hms_gpt_vps.pairing_exchange import PairingExchangeKey, PairingSessionExchange
from hms_gpt_vps.pairing_link_lease import PairingLinkLeaseStore
from hms_gpt_vps.pairing_readiness_runtime import (
    PairingReadinessConfig,
    PairingReadinessRuntime,
)
from hms_gpt_vps.pairing_store import PairingStore
from hms_gpt_vps.principal_agent_control_service import (
    PrincipalAgentControlAmbiguousError,
    PrincipalAgentControlApprovalRequiredError,
    PrincipalAgentControlService,
    PrincipalAgentControlUnavailableError,
    PrincipalControlState,
)
from hms_gpt_vps.principal_dispatch_intent import (
    PrincipalDispatchIntentStore,
)
from hms_gpt_vps.principal_pairing_service import (
    PrincipalSessionBindingStore,
    PrincipalPairingService,
    TrustedIntegrationPrincipal,
)
from hms_gpt_vps.provision_state import ProvisionState, ProvisionStateStore


NOW = datetime(2026, 8, 25, 6, 20, tzinfo=timezone.utc)
INSTANCE_ID = "hms-01"
BRIDGE_BASE_URL = "https://bridge.example"


class MemorySecretStore:
    def __init__(self) -> None:
        self.value: str | None = None

    def save_text(self, secret: str) -> None:
        self.value = secret

    def load_text(self) -> str:
        if self.value is None:
            raise FileNotFoundError("secret missing")
        return self.value


class MemoryBindingRegistry:
    def __init__(self) -> None:
        self._stores: dict[tuple[str, str], PrincipalSessionBindingStore] = {}

    def store_for(
        self,
        principal_sha256: str,
        instance_id: str,
    ) -> PrincipalSessionBindingStore:
        key = (principal_sha256, instance_id)
        if key not in self._stores:
            self._stores[key] = PrincipalSessionBindingStore(MemorySecretStore())
        return self._stores[key]


class PresenceReader:
    def __init__(self, presence: AgentPresence | None) -> None:
        self.presence = presence

    def get_presence(self, instance_id: str) -> AgentPresence | None:
        return self.presence


class Clock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def fresh_presence(at: datetime) -> AgentPresence:
    return AgentPresence(
        instance_id=INSTANCE_ID,
        device_id="device-01",
        boot_id="boot-01",
        connection_epoch=3,
        first_seen_at=at - timedelta(minutes=1),
        last_seen_at=at,
    )


def principal() -> TrustedIntegrationPrincipal:
    return TrustedIntegrationPrincipal(
        namespace="openai-app",
        subject="user-01",
    )


def build_stack(tmp_path: Path):
    auth_db = tmp_path / "auth.sqlite3"
    pairing_store = PairingStore(auth_db)
    session_store = ControlSessionStore(auth_db)
    exchange = PairingSessionExchange(
        pairing_store,
        session_store,
        PairingExchangeKey(b"K" * 32),
    )

    provision = ProvisionStateStore(tmp_path / "provision.json")
    provision.transition(
        instance_id=INSTANCE_ID,
        state=ProvisionState.INSTALL_SECRETS_CLEARED,
    )
    clock = Clock()
    presence_reader = PresenceReader(fresh_presence(clock.value))
    readiness = PairingReadinessRuntime(
        PairingReadinessConfig(
            instance_id=INSTANCE_ID,
            bridge_base_url=BRIDGE_BASE_URL,
        ),
        provision,
        presence_reader,
        pairing_store,
        PairingLinkLeaseStore(MemorySecretStore()),
        tmp_path / "pairing-issuance.lock",
        clock=clock,
    )
    issued = readiness.issue()
    pairing = PrincipalPairingService(
        readiness,
        exchange,
        MemoryBindingRegistry(),
        tmp_path / "principal-pairing.lock",
    )
    who = principal()
    pairing.pair(who, issued.pairing_link)

    credential = AgentDeviceCredential(
        instance_id=INSTANCE_ID,
        device_id="device-01",
        secret=b"S" * 32,
    )

    def request_resolver(instance_id: str, device_id: str) -> AgentDeviceCredential:
        if instance_id != INSTANCE_ID or device_id != credential.device_id:
            raise KeyError("unknown Agent")
        return credential

    def command_resolver(instance_id: str) -> AgentDeviceCredential:
        if instance_id != INSTANCE_ID:
            raise KeyError("unknown Agent")
        return credential

    agent_bridge = AgentBridgeService(
        AgentConnectionRegistry(tmp_path / "agent-presence.sqlite3"),
        AgentCommandStore(tmp_path / "agent-commands.sqlite3"),
        request_resolver,
        command_resolver,
    )
    idempotency = IdempotencyStore(tmp_path / "idempotency.sqlite3")
    gateway = ControlGateway(session_store, idempotency)
    intent_root = tmp_path / "dispatch-intents"
    intent_root.mkdir()
    intent_store = PrincipalDispatchIntentStore(intent_root)
    control = PrincipalAgentControlService(
        pairing,
        gateway,
        agent_bridge,
        intent_store,
        clock=clock,
    )
    return {
        "control": control,
        "pairing": pairing,
        "gateway": gateway,
        "agent_bridge": agent_bridge,
        "intent_root": intent_root,
        "clock": clock,
        "presence_reader": presence_reader,
        "principal": who,
    }


def keep_fresh(stack: dict, seconds: int) -> None:
    clock: Clock = stack["clock"]
    clock.value = NOW + timedelta(seconds=seconds)
    reader: PresenceReader = stack["presence_reader"]
    reader.presence = fresh_presence(clock.value)


def test_pending_retry_completion_and_digest_only_replay(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    control: PrincipalAgentControlService = stack["control"]
    bridge: AgentBridgeService = stack["agent_bridge"]
    who = stack["principal"]

    first = control.read_file(
        who,
        instance_id=INSTANCE_ID,
        request_id="req-read-01",
        path="hello.txt",
    )
    assert first.state is PrincipalControlState.PENDING

    second = control.read_file(
        who,
        instance_id=INSTANCE_ID,
        request_id="req-read-01",
        path="hello.txt",
    )
    assert second.state is PrincipalControlState.PENDING

    secret_content = "guest-file-content-must-not-enter-idempotency"
    result = AgentCommandResult(
        schema_version=AGENT_TRANSPORT_SCHEMA_VERSION,
        request_id="req-read-01",
        instance_id=INSTANCE_ID,
        outcome="ok",
        response={
            "ok": True,
            "path": "hello.txt",
            "encoding": "utf-8",
            "content": secret_content,
            "size": len(secret_content),
            "sha256": "a" * 64,
            "modified_utc": "2026-08-25T06:20:01+00:00",
        },
        completed_at=NOW + timedelta(seconds=1),
    )
    bridge.commands.complete(result, now=NOW + timedelta(seconds=1))
    keep_fresh(stack, 2)

    completed = control.read_file(
        who,
        instance_id=INSTANCE_ID,
        request_id="req-read-01",
        path="hello.txt",
    )
    assert completed.state is PrincipalControlState.COMPLETED
    assert completed.response is not None
    assert completed.response["content"] == secret_content

    replay = control.read_file(
        who,
        instance_id=INSTANCE_ID,
        request_id="req-read-01",
        path="hello.txt",
    )
    assert replay == completed

    with sqlite3.connect(stack["gateway"].idempotency_store.path) as connection:
        cached = connection.execute(
            "SELECT response_json FROM idempotency_records WHERE request_id = ?",
            ("req-read-01",),
        ).fetchone()[0]
    assert secret_content not in cached
    assert "result_sha256" in cached
    assert "command_sha256" in cached


def test_crash_after_claim_before_enqueue_resumes_from_older_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack = build_stack(tmp_path)
    control: PrincipalAgentControlService = stack["control"]
    bridge: AgentBridgeService = stack["agent_bridge"]
    who = stack["principal"]
    original_enqueue = bridge.enqueue_command

    def crash_before_enqueue(*args, **kwargs):
        raise RuntimeError("simulated Bridge crash boundary")

    monkeypatch.setattr(bridge, "enqueue_command", crash_before_enqueue)
    with pytest.raises(RuntimeError, match="simulated Bridge crash"):
        control.write_file(
            who,
            instance_id=INSTANCE_ID,
            request_id="req-write-crash",
            path="created.txt",
            content="hello",
        )

    monkeypatch.setattr(bridge, "enqueue_command", original_enqueue)
    keep_fresh(stack, 1)
    resumed = control.write_file(
        who,
        instance_id=INSTANCE_ID,
        request_id="req-write-crash",
        path="created.txt",
        content="hello",
    )
    assert resumed.state is PrincipalControlState.PENDING
    assert bridge.get_command_status(INSTANCE_ID, "req-write-crash") is not None


def test_unresolved_claim_that_predates_intent_fails_closed_without_enqueue(
    tmp_path: Path,
) -> None:
    stack = build_stack(tmp_path)
    control: PrincipalAgentControlService = stack["control"]
    pairing: PrincipalPairingService = stack["pairing"]
    gateway: ControlGateway = stack["gateway"]
    bridge: AgentBridgeService = stack["agent_bridge"]
    who = stack["principal"]
    binding = pairing.load_active_binding(who, INSTANCE_ID)
    request = ControlRequest(
        schema_version=CONTROL_REQUEST_SCHEMA_VERSION,
        request_id="req-cross-path",
        instance_id=INSTANCE_ID,
        session_id=binding.session_id,
        action="workspace.read",
        params={"path": "README.md"},
    )
    assert gateway.begin(
        request,
        binding.session_token,
        now=NOW,
    ).should_execute

    with pytest.raises(
        PrincipalAgentControlAmbiguousError,
        match="predates Agent dispatch intent",
    ):
        control.read_file(
            who,
            instance_id=INSTANCE_ID,
            request_id="req-cross-path",
            path="README.md",
        )

    assert bridge.get_command_status(INSTANCE_ID, "req-cross-path") is None


def test_stale_agent_rejected_before_intent_or_idempotency_claim(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    control: PrincipalAgentControlService = stack["control"]
    reader: PresenceReader = stack["presence_reader"]
    who = stack["principal"]
    reader.presence = fresh_presence(NOW - timedelta(minutes=10))

    with pytest.raises(
        PrincipalAgentControlUnavailableError,
        match="not currently fresh",
    ):
        control.read_file(
            who,
            instance_id=INSTANCE_ID,
            request_id="req-stale",
            path="README.md",
        )

    assert list(stack["intent_root"].iterdir()) == []
    with sqlite3.connect(stack["gateway"].idempotency_store.path) as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM idempotency_records WHERE request_id = ?",
            ("req-stale",),
        ).fetchone()[0]
    assert count == 0


def test_replace_requires_separate_approval_and_never_stages_command(tmp_path: Path) -> None:
    stack = build_stack(tmp_path)
    control: PrincipalAgentControlService = stack["control"]
    bridge: AgentBridgeService = stack["agent_bridge"]
    who = stack["principal"]

    with pytest.raises(
        PrincipalAgentControlApprovalRequiredError,
        match="separate explicit approval flow",
    ):
        control.submit(
            who,
            instance_id=INSTANCE_ID,
            request_id="req-replace",
            action="workspace.write",
            params={
                "path": "existing.txt",
                "content": "new",
                "mode": "replace",
                "expected_sha256": "a" * 64,
            },
        )

    assert list(stack["intent_root"].iterdir()) == []
    assert bridge.get_command_status(INSTANCE_ID, "req-replace") is None
