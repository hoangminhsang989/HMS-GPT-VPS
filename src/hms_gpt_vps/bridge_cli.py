from __future__ import annotations

import argparse
import json

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hms-bridge")
    parser.add_argument(
        "--version",
        action="version",
        version=f"hms-bridge {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "service",
        help="Run the HMS Bridge under Windows Service Control Manager",
    )
    subparsers.add_parser(
        "provision-oauth-introspection-credential",
        help="Provision the OAuth introspection client credential from stdin",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "service":
        # Production SCM configuration is fixed under ProgramData. Deliberately
        # accept no runtime-config path, credential, token, or secret override.
        from .bridge_service_entrypoint import run_hms_bridge_service_entrypoint

        run_hms_bridge_service_entrypoint()
        return 0
    if args.command == "provision-oauth-introspection-credential":
        # Deliberately accept no command options. The client secret is read only
        # from bounded stdin after elevated-admin and stopped-SCM preflight.
        from .bridge_oauth_provisioning_ingress import (
            provision_bridge_oauth_introspection_credential_from_stdin,
        )

        evidence = provision_bridge_oauth_introspection_credential_from_stdin()
        print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
