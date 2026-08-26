from __future__ import annotations

import argparse
import json
from pathlib import Path

from hms_gpt_vps.r002f_production_proof_gate import (
    verify_r002f_production_proof_bundle,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify and cross-bind already-produced R002F managed Hyper-V, "
            "Bridge activation, authenticated Agent transport, and OpenAI "
            "control-plane proof artifacts. This command does not start a VM, "
            "service, tunnel, or mutate provisioning state."
        )
    )
    parser.add_argument("--managed-hyperv-proof", required=True, type=Path)
    parser.add_argument("--composite-activation-proof", required=True, type=Path)
    parser.add_argument("--agent-transport-proof", required=True, type=Path)
    parser.add_argument("--openai-control-plane-proof", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    proof = verify_r002f_production_proof_bundle(
        managed_hyperv_proof_path=args.managed_hyperv_proof,
        composite_activation_proof_path=args.composite_activation_proof,
        agent_transport_proof_path=args.agent_transport_proof,
        openai_control_plane_proof_path=args.openai_control_plane_proof,
        output_proof_path=args.proof,
    )
    print(json.dumps(proof, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
