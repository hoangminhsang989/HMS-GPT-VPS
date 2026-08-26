from __future__ import annotations

import argparse
from pathlib import Path

from hms_gpt_vps.bridge_composite_activation_runner import (
    run_composite_activation_qualification,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify one HMSBridge TLS/MCP/Secure-MCP-Tunnel/managed-guest-TLS "
            "activation generation and return the service to Stopped/Manual."
        )
    )
    parser.add_argument("--trust-root-certificate", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_composite_activation_qualification(
        trust_root_certificate_path=args.trust_root_certificate,
        proof_path=args.proof,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
