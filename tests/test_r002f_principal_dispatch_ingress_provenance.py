from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3

import pytest

import hms_gpt_vps.principal_dispatch_ingress_provenance as module
from hms_gpt_vps.idempotency_store import IdempotencyStore
from hms_gpt_vps.principal_dispatch_intent import (
    PrincipalDispatchClaimState,
    PrincipalDispatchIntent,
    PrincipalDispatchIntentAmbiguousError,
)

NOW = datetime(2026, 8, 26, 8, 30, tzinfo=timezone.utc)
GEN1 = "a" * 32
GEN2 = "b" * 32


def intent(request_id="req-1"):
    return PrincipalDispatchIntent(
        schema_version=1,
        principal_sha256="1" * 64,
        pair_id="pair-1",
        session_id="session-1",
        session_epoch=3,
        instance_id="instance-1",
        request_id=request_id,
        request_sha256="2" * 64,
        command_sha256="3" * 64,
        expires_at=NOW + timedelta(minutes=5),
    )


def counts(store, request_id="req-1"):
    with sqlite3.connect(store.idempotency_store.path) as c:
        return tuple(
            c.execute(f"SELECT COUNT(*) FROM {table} WHERE request_id=?", (request_id,)).fetchone()[0]
            for table in (
                "idempotency_records",
                "principal_agent_dispatch_claims",
                "principal_dispatch_ingress_provenance",
            )
        )


def stored_generation(store):
    with sqlite3.connect(store.idempotency_store.path) as c:
        row=c.execute("SELECT mcp_ingress_generation FROM principal_dispatch_ingress_provenance WHERE request_id='req-1'").fetchone()
    return None if row is None else row[0]


def test_mcp_new_claim_atomically_persists_exact_provenance(tmp_path, monkeypatch):
    store=module.IngressProvenancePrincipalDispatchIntentStore(IdempotencyStore(tmp_path/"idem.sqlite3"))
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN1)
    claim=store.begin(intent(),now=NOW)
    assert claim.state is PrincipalDispatchClaimState.NEW
    assert counts(store)==(1,1,1)
    assert stored_generation(store)==GEN1


def test_direct_new_claim_has_no_provenance_and_cannot_be_laundered_by_mcp_retry(tmp_path, monkeypatch):
    store=module.IngressProvenancePrincipalDispatchIntentStore(IdempotencyStore(tmp_path/"idem.sqlite3"))
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:None)
    assert store.begin(intent(),now=NOW).state is PrincipalDispatchClaimState.NEW
    assert counts(store)==(1,1,0)
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN1)
    with pytest.raises(PrincipalDispatchIntentAmbiguousError,match="lacks atomic MCP ingress provenance"):
        store.begin(intent(),now=NOW+timedelta(seconds=1))
    assert counts(store)==(1,1,0)


def test_mcp_proven_claim_cannot_resume_via_direct_path(tmp_path, monkeypatch):
    store=module.IngressProvenancePrincipalDispatchIntentStore(IdempotencyStore(tmp_path/"idem.sqlite3"))
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN1)
    store.begin(intent(),now=NOW)
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:None)
    with pytest.raises(PrincipalDispatchIntentAmbiguousError,match="cannot resume outside"):
        store.begin(intent(),now=NOW+timedelta(seconds=1))


def test_mcp_retry_through_later_generation_preserves_original_provenance(tmp_path, monkeypatch):
    store=module.IngressProvenancePrincipalDispatchIntentStore(IdempotencyStore(tmp_path/"idem.sqlite3"))
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN1)
    store.begin(intent(),now=NOW)
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN2)
    claim=store.begin(intent(),now=NOW+timedelta(seconds=1))
    assert claim.state is PrincipalDispatchClaimState.RESUME
    assert stored_generation(store)==GEN1
    assert counts(store)==(1,1,1)


def test_provenance_insert_failure_rolls_back_idempotency_and_dispatch(tmp_path, monkeypatch):
    store=module.IngressProvenancePrincipalDispatchIntentStore(IdempotencyStore(tmp_path/"idem.sqlite3"))
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN1)
    monkeypatch.setattr(module.McpIngressDispatchProvenance,"to_row",lambda self: (_ for _ in ()).throw(RuntimeError("fail before provenance insert")))
    with pytest.raises(RuntimeError,match="fail before provenance insert"):
        store.begin(intent(),now=NOW)
    assert counts(store)==(0,0,0)


def test_tampered_provenance_digest_fails_closed(tmp_path, monkeypatch):
    store=module.IngressProvenancePrincipalDispatchIntentStore(IdempotencyStore(tmp_path/"idem.sqlite3"))
    monkeypatch.setattr(module,"current_mcp_tunnel_ingress_generation",lambda:GEN1)
    store.begin(intent(),now=NOW)
    with sqlite3.connect(store.idempotency_store.path) as c:
        c.execute("UPDATE principal_dispatch_ingress_provenance SET command_sha256=? WHERE request_id='req-1'",("4"*64,)); c.commit()
    with pytest.raises(PrincipalDispatchIntentAmbiguousError,match="differs from exact"):
        store.begin(intent(),now=NOW+timedelta(seconds=1))


def test_preexisting_provenance_table_schema_drift_is_rejected(tmp_path):
    idem = IdempotencyStore(tmp_path / "idem.sqlite3")
    with sqlite3.connect(idem.path) as connection:
        connection.execute(
            "CREATE TABLE principal_dispatch_ingress_provenance (session_id TEXT, request_id TEXT)"
        )
        connection.commit()
    with pytest.raises(
        module.PrincipalDispatchIntentError,
        match="table schema differs from authority",
    ):
        module.IngressProvenancePrincipalDispatchIntentStore(idem)
