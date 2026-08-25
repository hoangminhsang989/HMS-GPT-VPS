from __future__ import annotations

import argparse
from pathlib import Path

from hms_gpt_vps import __version__
from hms_gpt_vps.bridge_package import (
    build_bridge_package_manifest,
    load_bridge_package_manifest,
    require_bridge_windows_amd64_pe,
    verify_bridge_package,
    write_bridge_package_manifest,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attest the complete packaged HMSBridge Windows x64 onedir tree"
    )
    parser.add_argument("package_root", type=Path)
    parser.add_argument("manifest", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    package_root = args.package_root
    manifest_path = args.manifest.resolve()

    manifest = build_bridge_package_manifest(package_root, version=__version__)
    require_bridge_windows_amd64_pe(package_root / manifest.entrypoint)
    write_bridge_package_manifest(manifest_path, manifest)

    published = load_bridge_package_manifest(manifest_path)
    verify_bridge_package(package_root, published)
    require_bridge_windows_amd64_pe(package_root / published.entrypoint)

    print(published.to_json())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
