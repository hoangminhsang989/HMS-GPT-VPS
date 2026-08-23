from __future__ import annotations

import argparse
from pathlib import Path

from .health import health_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hms-gpt-vps")
    subparsers = parser.add_subparsers(dest="command", required=True)

    health = subparsers.add_parser("health", help="Print agent health as JSON")
    health.add_argument("--workspace", type=Path, default=Path.cwd())
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "health":
        print(health_json(args.workspace))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
