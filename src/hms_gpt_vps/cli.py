from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .health import health_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hms-agent")
    parser.add_argument(
        "--version",
        action="version",
        version=f"hms-agent {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    health = subparsers.add_parser("health", help="Print agent health as JSON")
    health.add_argument("--workspace", type=Path, default=Path.cwd())

    subparsers.add_parser(
        "service",
        help="Run the HMS Agent under Windows Service Control Manager",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "health":
        print(health_json(args.workspace))
        return 0
    if args.command == "service":
        # Import lazily so ordinary cross-platform CLI commands do not construct
        # native Windows SCM objects. The service command intentionally accepts
        # no runtime-config path override; the SCM host uses the protected fixed
        # Agent-root config location.
        from .agent_windows_service_host import run_hms_agent_windows_service

        run_hms_agent_windows_service()
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
