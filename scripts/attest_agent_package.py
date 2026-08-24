from __future__ import annotations

import argparse
from pathlib import Path

from hms_gpt_vps import __version__
from hms_gpt_vps.agent_package import (
    build_agent_package_manifest,
    load_agent_package_manifest,
    require_windows_amd64_pe,
    verify_agent_package,
    write_agent_package_manifest,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attest one packaged HMS Agent Windows x64 executable"
    )
    parser.add_argument("executable", type=Path)
    parser.add_argument("manifest", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    executable = args.executable.resolve()
    manifest_path = args.manifest.resolve()

    if executable.name != "hms-agent.exe":
        raise ValueError("production Agent artifact must be named hms-agent.exe")

    require_windows_amd64_pe(executable)
    manifest = build_agent_package_manifest(executable, version=__version__)
    write_agent_package_manifest(manifest_path, manifest)

    published = load_agent_package_manifest(manifest_path)
    verify_agent_package(executable, published)
    require_windows_amd64_pe(executable)

    print(published.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
