from __future__ import annotations

import json
import platform
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class HealthReport:
    status: str
    python: str
    platform: str
    git_available: bool
    workspace_exists: bool


def collect_health(workspace_root: Path) -> HealthReport:
    exists = workspace_root.expanduser().exists()
    git_available = shutil.which("git") is not None
    return HealthReport(
        status="ok" if exists and git_available else "degraded",
        python=platform.python_version(),
        platform=platform.platform(),
        git_available=git_available,
        workspace_exists=exists,
    )


def health_json(workspace_root: Path) -> str:
    return json.dumps(asdict(collect_health(workspace_root)), sort_keys=True)
