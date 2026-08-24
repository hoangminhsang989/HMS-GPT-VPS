from __future__ import annotations

import argparse
from pathlib import Path

from hms_gpt_vps import __version__
from hms_gpt_vps.agent_package import (
    AGENT_PACKAGE_ENTRYPOINT,
    build_agent_package_manifest,
    load_agent_package_manifest,
    require_windows_amd64_pe,
    verify_agent_package,
    write_agent_package_manifest,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attest the complete packaged HMS Agent Windows x64 onedir tree"
    )
    parser.add_argument("package_root", type=Path)
    parser.add_argument("manifest", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    package_root = args.package_root.resolve(strict=True)
    manifest_path = args.manifest.resolve()
    if not package_root.is_dir():
        raise ValueError("production Agent package root must be a directory")

    entrypoint = package_root / AGENT_PACKAGE_ENTRYPOINT
    require_windows_amd64_pe(entrypoint)
    manifest = build_agent_package_manifest(package_root, version=__version__)
    write_agent_package_manifest(manifest_path, manifest)

    published = load_agent_package_manifest(manifest_path)
    verify_agent_package(package_root, published)
    require_windows_amd64_pe(package_root / published.entrypoint)

    print(published.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
