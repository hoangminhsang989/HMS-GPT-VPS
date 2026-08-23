import json
from pathlib import Path

from hms_gpt_vps.audit import AuditLog


def test_audit_log_appends_jsonl(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append(action="git.status", project_id="p1", outcome="ok", returncode=0)

    record = json.loads(path.read_text(encoding="utf-8").strip())
    assert record["action"] == "git.status"
    assert record["project_id"] == "p1"
    assert record["outcome"] == "ok"
    assert record["detail"]["returncode"] == 0
    assert record["timestamp"]
