from pathlib import Path

import pytest

from hms_gpt_vps.workspace import Workspace, WorkspaceViolation


def test_resolve_stays_inside_workspace(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    assert workspace.resolve(Path("a") / "b.txt") == (tmp_path / "a" / "b.txt").resolve()


def test_absolute_escape_is_rejected(tmp_path: Path) -> None:
    workspace = Workspace(project_id="p1", root=tmp_path)
    outside = tmp_path.parent / "outside.txt"
    with pytest.raises(WorkspaceViolation):
        workspace.resolve(outside)
