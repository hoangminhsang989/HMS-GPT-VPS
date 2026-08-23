from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


class WorkspaceViolation(ValueError):
    """Raised when a requested path escapes the configured project root."""


@dataclass(frozen=True)
class Workspace:
    project_id: str
    root: Path

    def __post_init__(self) -> None:
        if not self.project_id.strip():
            raise ValueError("project_id is required")
        object.__setattr__(self, "root", self.root.expanduser().resolve())

    def resolve(self, relative_path: str | Path = ".") -> Path:
        candidate = (self.root / Path(relative_path)).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise WorkspaceViolation(f"path escapes workspace: {relative_path}") from exc
        return candidate
