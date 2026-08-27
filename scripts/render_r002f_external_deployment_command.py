from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

sys.dont_write_bytecode = True


def _bootstrap() -> None:
    root = Path(__file__).resolve().parents[1]
    src = root / "src"
    sys.path.insert(0, str(src))


_bootstrap()

from hms_gpt_vps.r002f_external_deployment_bundle import (
    R002FExternalDeploymentAuthorityBundle,
    render_os_trusted_launcher_command,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate an R002F external deployment authority bundle and render the OS-trusted launcher command."
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    args = parser.parse_args(argv)

    data = args.bundle.read_bytes()
    observed = hashlib.sha256(data).hexdigest()
    if observed != args.bundle_sha256:
        raise SystemExit("deployment bundle SHA-256 differs from supplied authority")
    bundle = R002FExternalDeploymentAuthorityBundle.from_bytes(data)
    if bundle.sha256 != observed:
        raise SystemExit("deployment bundle is not in canonical byte form")
    print(render_os_trusted_launcher_command(bundle))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
