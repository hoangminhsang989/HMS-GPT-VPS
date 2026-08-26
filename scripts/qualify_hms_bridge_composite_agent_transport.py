from __future__ import annotations

import argparse
from pathlib import Path

from hms_gpt_vps.bridge_composite_agent_transport_runner import (
    run_composite_agent_transport_qualification,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify Secure MCP Tunnel stability across authenticated HMSAgent "
            "hello/heartbeat/poll/result and return HMSBridge to Stopped/Manual."
        )
    )
    parser.add_argument("--proof", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_composite_agent_transport_qualification(proof_path=args.proof)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
