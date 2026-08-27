from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Read-only R002F preflight from sealed project/Python/Git runtime authority."
        )
    )
    p.add_argument("--repo-evidence-root", required=True, type=Path)
    p.add_argument("--execution-root", required=True, type=Path)
    p.add_argument("--execution-manifest", required=True, type=Path)
    p.add_argument("--execution-manifest-sha256", required=True)
    p.add_argument("--python-runtime-root", required=True, type=Path)
    p.add_argument("--python-runtime-manifest", required=True, type=Path)
    p.add_argument("--python-runtime-manifest-sha256", required=True)
    p.add_argument("--git-runtime-root", required=True, type=Path)
    p.add_argument("--git-runtime-manifest", required=True, type=Path)
    p.add_argument("--git-runtime-manifest-sha256", required=True)
    p.add_argument("--reviewed-runner-source-commit", required=True)
    p.add_argument("--proof", required=True, type=Path)
    p.add_argument("--run-dir", type=Path)
    p.add_argument("--package-root", type=Path)
    p.add_argument("--package-manifest", type=Path)
    p.add_argument("--runtime-config", type=Path)
    p.add_argument("--instance-registry", type=Path)
    p.add_argument("--instance-runtime-dir", type=Path)
    p.add_argument("--bridge-device-credential", type=Path)
    p.add_argument("--trust-root-certificate", type=Path)
    p.add_argument("--challenge-source-commit")
    p.add_argument("--challenge-workspace-path")
    p.add_argument("--challenge-expected-sha256")
    p.add_argument("--max-reconcile-steps", type=int, default=8)
    p.add_argument("--external-timeout", type=float, default=300.0)
    p.add_argument("--step-timeout", type=float, default=900.0)
    return p
