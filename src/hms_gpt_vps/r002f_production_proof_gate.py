from __future__ import annotations

from dataclasses import fields
import hashlib
import json
from pathlib import Path
from typing import Mapping

from .bridge_composite_activation_runner import validate_composite_activation_result
from .bridge_composite_agent_transport_runner import (
    validate_composite_agent_transport_result,
)
from .bridge_openai_control_plane_command_flow_runner import (
    validate_openai_control_plane_command_flow_result,
)
from .managed_hyperv_agent_qualification import ManagedHyperVAgentQualificationProof
from .managed_hyperv_agent_strict_qualification import (
    validate_strict_managed_hyperv_proof_payload,
)
from .qualification_file_authority import read_file_pinned, write_json_create_only

_PROOF_SCHEMA_VERSION = 1
_MAX_INPUT_PROOF_BYTES = 128 * 1024
_MAX_OUTPUT_PROOF_BYTES = 64 * 1024
_STRICT_MANAGED_EXTRA_KEYS = frozenset(
    {
        "strict_publication_schema_version",
        "os_listener_proven",
        "device_enrollment_reproven_at_publication",
        "health_listener_process_id",
        "health_listener_count",
        "health_listener_addresses",
        "health_listener_port",
    }
)


class R002FProductionProofGateError(RuntimeError):
    pass


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"unsupported JSON constant: {value}")


def _pairs(items: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in items:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _load_json_object(path: Path, *, label: str) -> tuple[dict[str, object], str]:
    if not isinstance(path, Path):
        raise TypeError(f"{label} path must be pathlib.Path")
    raw = read_file_pinned(
        path,
        max_bytes=_MAX_INPUT_PROOF_BYTES,
        label=label,
        allow_empty=False,
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise R002FProductionProofGateError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise R002FProductionProofGateError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict):
        raise R002FProductionProofGateError(f"{label} top level must be an object")
    digest = hashlib.sha256(raw).hexdigest()
    return value, digest


def _require_outer_proof(
    proof: Mapping[str, object],
    *,
    expected_keys: frozenset[str],
    qualification: str,
    status: str,
    label: str,
) -> dict[str, object]:
    if not isinstance(proof, Mapping) or frozenset(proof) != expected_keys:
        raise R002FProductionProofGateError(f"{label} proof schema is invalid")
    schema_version = proof.get("schema_version")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version != _PROOF_SCHEMA_VERSION
    ):
        raise R002FProductionProofGateError(f"{label} proof schema version differs")
    if proof.get("qualification") != qualification:
        raise R002FProductionProofGateError(f"{label} qualification differs")
    if proof.get("status") != status:
        raise R002FProductionProofGateError(f"{label} status differs")
    result = proof.get("result")
    if not isinstance(result, dict):
        raise R002FProductionProofGateError(f"{label} result is missing")
    return result


def _validate_managed_hyperv_proof(
    payload: dict[str, object],
) -> dict[str, object]:
    base_names = frozenset(field.name for field in fields(ManagedHyperVAgentQualificationProof))
    expected_names = base_names | _STRICT_MANAGED_EXTRA_KEYS
    if frozenset(payload) != expected_names:
        raise R002FProductionProofGateError(
            "managed Hyper-V strict proof schema is invalid"
        )
    base_payload = {name: payload[name] for name in base_names}
    actions = base_payload.get("actions")
    capabilities = base_payload.get("health_capabilities")
    if not isinstance(actions, list) or not isinstance(capabilities, list):
        raise R002FProductionProofGateError(
            "managed Hyper-V list-valued proof fields are invalid"
        )
    base_payload["actions"] = tuple(actions)
    base_payload["health_capabilities"] = tuple(capabilities)
    try:
        base = ManagedHyperVAgentQualificationProof(**base_payload)
        base.validate()
        validate_strict_managed_hyperv_proof_payload(payload)
    except Exception as exc:
        raise R002FProductionProofGateError(
            "managed Hyper-V strict proof failed validation"
        ) from exc
    return dict(payload)


def _validated_bundle_inputs(
    *,
    managed_hyperv_proof: dict[str, object],
    composite_activation_proof: dict[str, object],
    agent_transport_proof: dict[str, object],
    openai_control_plane_proof: dict[str, object],
) -> tuple[
    dict[str, object],
    dict[str, object],
    dict[str, object],
    dict[str, object],
]:
    managed = _validate_managed_hyperv_proof(managed_hyperv_proof)

    activation_result = _require_outer_proof(
        composite_activation_proof,
        expected_keys=frozenset({"schema_version", "qualification", "status", "result"}),
        qualification="R002F_HMSBRIDGE_COMPOSITE_ACTIVATION",
        status="QUALIFIED_STOPPED",
        label="composite activation",
    )
    transport_result = _require_outer_proof(
        agent_transport_proof,
        expected_keys=frozenset({"schema_version", "qualification", "status", "result"}),
        qualification="R002F_AUTHENTICATED_AGENT_TRANSPORT_WITH_SECURE_TUNNEL",
        status="AUTHENTICATED_AGENT_TRANSPORT_WITH_TUNNEL_QUALIFIED_STOPPED",
        label="authenticated Agent transport",
    )
    openai_result = _require_outer_proof(
        openai_control_plane_proof,
        expected_keys=frozenset(
            {"schema_version", "qualification", "status", "challenge_path", "result"}
        ),
        qualification="R002F_OPENAI_CONTROL_PLANE_COMMAND_FLOW",
        status="OPENAI_CONTROL_PLANE_PRINCIPAL_READ_QUALIFIED_STOPPED",
        label="OpenAI control-plane command flow",
    )
    challenge_path = openai_control_plane_proof.get("challenge_path")
    if not isinstance(challenge_path, str) or not challenge_path.strip():
        raise R002FProductionProofGateError(
            "OpenAI control-plane challenge path is invalid"
        )

    try:
        activation = validate_composite_activation_result(activation_result)
        transport = validate_composite_agent_transport_result(transport_result)
        openai = validate_openai_control_plane_command_flow_result(openai_result)
    except Exception as exc:
        raise R002FProductionProofGateError(
            "one or more component proof validators rejected the bundle"
        ) from exc
    return managed, activation, transport, openai


def bind_r002f_production_proofs(
    *,
    managed: Mapping[str, object],
    activation: Mapping[str, object],
    transport: Mapping[str, object],
    openai: Mapping[str, object],
    managed_proof_sha256: str,
    activation_proof_sha256: str,
    transport_proof_sha256: str,
    openai_proof_sha256: str,
) -> dict[str, object]:
    instance_id = managed.get("instance_id")
    vm_id = managed.get("vm_id")
    device_id = managed.get("device_id")
    if not isinstance(instance_id, str) or not instance_id.strip():
        raise R002FProductionProofGateError("managed proof instance_id is invalid")
    if not isinstance(vm_id, str) or not vm_id.strip():
        raise R002FProductionProofGateError("managed proof vm_id is invalid")
    if not isinstance(device_id, str) or not device_id.strip():
        raise R002FProductionProofGateError("managed proof device_id is invalid")

    def canonical_vm_id(value: object, *, label: str) -> str:
        if not isinstance(value, str) or len(value) != 36 or value != value.lower():
            raise R002FProductionProofGateError(f"{label} VMId is noncanonical")
        expected_hyphens = {8, 13, 18, 23}
        for index, char in enumerate(value):
            if index in expected_hyphens:
                if char != "-":
                    raise R002FProductionProofGateError(f"{label} VMId is noncanonical")
            elif char not in "0123456789abcdef":
                raise R002FProductionProofGateError(f"{label} VMId is noncanonical")
        return value

    managed_vm_id = canonical_vm_id(vm_id, label="managed proof")
    activation_vm_id = canonical_vm_id(
        activation.get("vm_id"),
        label="composite activation proof",
    )
    if activation_vm_id != managed_vm_id:
        raise R002FProductionProofGateError(
            "Hyper-V VM identity differs across managed guest and Bridge activation proofs"
        )
    transport_device_id = transport.get("agent_device_id")
    if transport_device_id != device_id:
        raise R002FProductionProofGateError(
            "Agent device identity differs across managed guest and authenticated transport proofs"
        )
    managed_boot_id = managed.get("health_boot_id")
    transport_boot_id = transport.get("agent_boot_id")
    if (
        not isinstance(managed_boot_id, str)
        or not managed_boot_id.strip()
        or transport_boot_id != managed_boot_id
    ):
        raise R002FProductionProofGateError(
            "Agent service incarnation differs across managed guest and authenticated transport proofs"
        )
    openai_instance_id = openai.get("instance_id")
    if openai_instance_id != instance_id:
        raise R002FProductionProofGateError(
            "instance identity differs across managed guest and OpenAI control-plane proofs"
        )
    tunnel_digests = (
        activation.get("tunnel_executable_sha256"),
        transport.get("tunnel_executable_sha256"),
        openai.get("tunnel_executable_sha256"),
    )
    if (
        any(
            not isinstance(value, str)
            or len(value) != 64
            or value != value.lower()
            or any(char not in "0123456789abcdef" for char in value)
            for value in tunnel_digests
        )
        or len(set(tunnel_digests)) != 1
    ):
        raise R002FProductionProofGateError(
            "OpenAI tunnel executable authority differs across live proof layers"
        )

    for key, value in (
        ("managed_proof_sha256", managed_proof_sha256),
        ("activation_proof_sha256", activation_proof_sha256),
        ("transport_proof_sha256", transport_proof_sha256),
        ("openai_proof_sha256", openai_proof_sha256),
    ):
        if (
            not isinstance(value, str)
            or len(value) != 64
            or value != value.lower()
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise R002FProductionProofGateError(f"{key} is noncanonical")

    source_commit = openai.get("source_commit")
    if (
        not isinstance(source_commit, str)
        or len(source_commit) != 40
        or source_commit != source_commit.lower()
        or any(char not in "0123456789abcdef" for char in source_commit)
    ):
        raise R002FProductionProofGateError("OpenAI proof source_commit is invalid")

    return {
        "schema_version": _PROOF_SCHEMA_VERSION,
        "qualification": "R002F_PRODUCTION_CROSS_PROOF_GATE",
        "status": "CROSS_PROOF_IDENTITY_BOUND_STAGED",
        "instance_id": instance_id,
        "vm_id": managed_vm_id,
        "device_id": device_id,
        "agent_boot_id": managed_boot_id,
        "tunnel_executable_sha256": tunnel_digests[0],
        "source_commit": source_commit,
        "managed_hyperv_proof_sha256": managed_proof_sha256,
        "composite_activation_proof_sha256": activation_proof_sha256,
        "authenticated_agent_transport_proof_sha256": transport_proof_sha256,
        "openai_control_plane_proof_sha256": openai_proof_sha256,
        "hyperv_guest_proven": True,
        "live_managed_guest_tls_proven": True,
        "authenticated_agent_transport_proven": True,
        "openai_control_plane_origin_proven": True,
        "durable_external_principal_read_proven": True,
        "cross_proof_identity_binding_proven": True,
        "chatgpt_ui_origin_proven": False,
        "token_specific_client_auth_attestation_proven": False,
        "token_endpoint_private_key_jwt_exchange_proven": False,
        "chatgpt_app_oauth_client_proven": False,
        "full_bridge_command_flow_proven": False,
        "bootstrap_retired": False,
        "pairing_ready": False,
        "automatic_start_enabled": False,
    }


def verify_r002f_production_proof_bundle(
    *,
    managed_hyperv_proof_path: Path,
    composite_activation_proof_path: Path,
    agent_transport_proof_path: Path,
    openai_control_plane_proof_path: Path,
    output_proof_path: Path,
) -> dict[str, object]:
    paths = (
        managed_hyperv_proof_path,
        composite_activation_proof_path,
        agent_transport_proof_path,
        openai_control_plane_proof_path,
        output_proof_path,
    )
    if any(not isinstance(path, Path) for path in paths):
        raise TypeError("all proof paths must be pathlib.Path")
    lexical = [path.expanduser().absolute() for path in paths]
    if len(set(lexical)) != len(lexical):
        raise R002FProductionProofGateError("all proof paths must be distinct")

    managed_raw, managed_digest = _load_json_object(
        managed_hyperv_proof_path,
        label="strict managed Hyper-V proof",
    )
    activation_raw, activation_digest = _load_json_object(
        composite_activation_proof_path,
        label="HMSBridge composite activation proof",
    )
    transport_raw, transport_digest = _load_json_object(
        agent_transport_proof_path,
        label="authenticated Agent transport proof",
    )
    openai_raw, openai_digest = _load_json_object(
        openai_control_plane_proof_path,
        label="OpenAI control-plane command-flow proof",
    )
    managed, activation, transport, openai = _validated_bundle_inputs(
        managed_hyperv_proof=managed_raw,
        composite_activation_proof=activation_raw,
        agent_transport_proof=transport_raw,
        openai_control_plane_proof=openai_raw,
    )
    proof = bind_r002f_production_proofs(
        managed=managed,
        activation=activation,
        transport=transport,
        openai=openai,
        managed_proof_sha256=managed_digest,
        activation_proof_sha256=activation_digest,
        transport_proof_sha256=transport_digest,
        openai_proof_sha256=openai_digest,
    )
    write_json_create_only(
        output_proof_path,
        proof,
        max_bytes=_MAX_OUTPUT_PROOF_BYTES,
        label="R002F production cross-proof gate",
    )
    return proof
