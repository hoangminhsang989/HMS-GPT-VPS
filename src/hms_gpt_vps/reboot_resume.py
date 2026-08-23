from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path


@dataclass(frozen=True)
class ResumeState:
    revision: str
    phase: str
    instance_id: str
    reason: str


class ResumeStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def save(self, state: ResumeState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(asdict(state), indent=2, sort_keys=True), encoding="utf-8")
        temp.replace(self.path)

    def load(self) -> ResumeState | None:
        if not self.path.exists():
            return None
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        return ResumeState(**raw)

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()
