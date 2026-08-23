from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile


@dataclass(frozen=True)
class VMRecord:
    instance_id: str
    vm_name: str
    backend: str
    phase: str
    workspace_path: str
    vm_id: str | None = None
    switch_name: str | None = None
    guest_ipv4: str | None = None


class InstanceRegistry:
    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> dict[str, VMRecord]:
        if not self.path.exists():
            return {}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("registry root must be an object")
        return {key: VMRecord(**value) for key, value in data.items()}

    def get(self, instance_id: str) -> VMRecord | None:
        return self.load().get(instance_id)

    def upsert(self, record: VMRecord) -> None:
        if not record.instance_id.strip():
            raise ValueError("instance_id is required")
        if not record.vm_name.strip():
            raise ValueError("vm_name is required")
        records = self.load()
        existing = records.get(record.instance_id)
        if (
            existing is not None
            and existing.vm_id is not None
            and record.vm_id is not None
            and existing.vm_id != record.vm_id
        ):
            raise ValueError("refusing to replace persisted VM identity with a different VMId")
        records[record.instance_id] = record
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {key: asdict(value) for key, value in sorted(records.items())}
        with NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=self.path.parent,
            prefix=self.path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            temp_path = Path(handle.name)
        temp_path.replace(self.path)
