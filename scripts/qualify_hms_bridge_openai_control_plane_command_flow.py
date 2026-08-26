from __future__ import annotations

import argparse
from pathlib import Path

from hms_gpt_vps.bridge_openai_control_plane_command_flow_runner import (
    run_openai_control_plane_command_flow_qualification,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Qualify one protected external HMS read as originating from the "
            "authenticated OpenAI tunnel control plane under the reviewed "
            "HMSBridge host/service trust boundary. This does not prove a "
            "specific ChatGPT UI/user gesture and does not enable full-flow readiness."
        )
    )
    parser.add_argument("--challenge", required=True, type=Path)
    parser.add_argument("--proof", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--timeout", type=float, default=300.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_openai_control_plane_command_flow_qualification(
        challenge_path=args.challenge,
        proof_path=args.proof,
        source_commit=args.source_commit,
        path=args.path,
        expected_content_sha256=args.expected_sha256,
        external_timeout_seconds=args.timeout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
