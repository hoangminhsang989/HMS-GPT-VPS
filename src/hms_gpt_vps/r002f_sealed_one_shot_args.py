from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Run R002F one-shot only from sealed project + Python runtime authority."
        )
    )
    p.add_argument("--execution-root", required=True, type=Path)
    p.add_argument("--execution-manifest", required=True, type=Path)
    p.add_argument("--execution-manifest-sha256", required=True)
    p.add_argument("--python-runtime-root", required=True, type=Path)
    p.add_argument("--python-runtime-manifest", required=True, type=Path)
    p.add_argument("--python-runtime-manifest-sha256", required=True)
    p.add_argument("--run-dir", required=True, type=Path)
    p.add_argument("--runner-source-commit", required=True)
    p.add_argument("--instance-id", required=True)
    p.add_argument("--vm-name", required=True)
    p.add_argument("--package-root", required=True, type=Path)
    p.add_argument("--package-manifest", required=True, type=Path)
    p.add_argument("--runtime-config", required=True, type=Path)
    p.add_argument("--instance-registry", required=True, type=Path)
    p.add_argument("--provision-state", required=True, type=Path)
    p.add_argument("--instance-runtime-dir", required=True, type=Path)
    p.add_argument("--bridge-device-credential", required=True, type=Path)
    p.add_argument("--trust-root-certificate", required=True, type=Path)
    p.add_argument("--challenge-source-commit", required=True)
    p.add_argument("--challenge-workspace-path", required=True)
    p.add_argument("--challenge-expected-sha256", required=True)
    p.add_argument("--max-reconcile-steps", type=int, default=8)
    p.add_argument("--external-timeout", type=float, default=300.0)
    p.add_argument("--step-timeout", type=float, default=900.0)
    return p
