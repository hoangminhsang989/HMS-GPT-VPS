from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuditEvent:
    action: str
    project_id: str
    outcome: str
    detail: dict[str, Any]
    timestamp: str


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, *, action: str, project_id: str, outcome: str, **detail: Any) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        event = AuditEvent(
            action=action,
            project_id=project_id,
            outcome=outcome,
            detail=detail,
            timestamp=utc_now_iso(),
        )
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event), ensure_ascii=False, sort_keys=True) + "\n")
