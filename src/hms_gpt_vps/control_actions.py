from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from typing import Any, Mapping

from .audit import AuditLog
from .control_request import ControlRequest
from .executor import CommandResult, ExecutionDenied, run_command
from .policy import Decision, PolicyRequest, evaluate
from .workspace import Workspace


MAX_WORKSPACE_READ_BYTES = 1024 * 1024
MAX_WORKSPACE_WRITE_BYTES = 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
MAX_AUDIT_EVENTS = 100
_SAFE_MAXFAIL = re.compile(r"^[1-9][0-9]{0,2}$")
_PATH_SPLIT = re.compile(r"[\\/]+")


class ControlActionError(RuntimeError):
    pass


class ControlActionPreconditionError(ControlActionError):
    pass


@dataclass(frozen=True)
class ControlActionRuntime:
    instance_id: str
    workspace: Workspace
    audit_log: AuditLog
    python_executable: str = "python"

    def __post_init__(self) -> None:
        if not self.instance_id.strip():
            raise ValueError("instance_id is required")
        if not self.python_executable.strip():
            raise ValueError("python_executable is required")

    def _require_instance(self, request: ControlRequest) -> None:
        if request.instance_id != self.instance_id:
            raise PermissionError("control request targets another managed instance")

    def _require_policy(
        self,
        capability: str,
        *,
        destructive: bool = False,
        explicitly_approved: bool = False,
    ) -> None:
        decision = evaluate(
            PolicyRequest(
                capability=capability,
                project_id=self.workspace.project_id,
                destructive=destructive,
                explicitly_approved=explicitly_approved,
            )
        )
        if decision is not Decision.ALLOW:
            self.audit_log.append(
                action=capability,
                project_id=self.workspace.project_id,
                outcome=decision.value,
                destructive=destructive,
            )
            raise ExecutionDenied(f"action blocked by policy: {decision.value}")

    @staticmethod
    def _relative_path(params: Mapping[str, Any]) -> str:
        raw = params.get("path")
        if not isinstance(raw, str) or not raw.strip():
            raise ControlActionPreconditionError("path must be a non-empty string")
        if raw in {".", "./", ".\\"}:
            raise ControlActionPreconditionError("path must identify a file")
        return raw

    @staticmethod
    def _reject_protected_write_path(relative: str) -> None:
        # workspace.write is intentionally a source/content capability, not a
        # Git metadata mutation surface.  Treat both slash styles as separators
        # so this stays fail-closed on Windows even when tests run on POSIX.
        for raw_part in _PATH_SPLIT.split(relative):
            normalized = raw_part.rstrip(" .").casefold()
            if normalized == ".git" or normalized.startswith(".git:"):
                raise ControlActionPreconditionError(
                    "workspace.write refuses paths inside Git metadata"
                )

    @staticmethod
    def _bounded_output(value: str) -> tuple[str, bool, int]:
        encoded = value.encode("utf-8", errors="replace")
        original_bytes = len(encoded)
        if original_bytes <= MAX_COMMAND_OUTPUT_BYTES:
            return value, False, original_bytes
        bounded = encoded[:MAX_COMMAND_OUTPUT_BYTES].decode("utf-8", errors="ignore")
        return bounded, True, original_bytes

    @classmethod
    def _command_response(cls, result: CommandResult) -> dict[str, Any]:
        stdout, stdout_truncated, stdout_bytes = cls._bounded_output(result.stdout)
        stderr, stderr_truncated, stderr_bytes = cls._bounded_output(result.stderr)
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "stdout_bytes": stdout_bytes,
            "stderr_bytes": stderr_bytes,
        }

    def execute(
        self,
        request: ControlRequest,
        *,
        explicitly_approved: bool = False,
    ) -> dict[str, Any]:
        request.validate()
        self._require_instance(request)
        if request.action == "workspace.read":
            return self._workspace_read(request.params)
        if request.action == "workspace.write":
            return self._workspace_write(
                request.params,
                explicitly_approved=explicitly_approved,
            )
        if request.action == "process.test":
            return self._process_test(request.params)
        if request.action == "git.status":
            return self._git_status()
        if request.action == "audit.read":
            return self._audit_read(request.params)
        raise ControlActionPreconditionError(f"unsupported action: {request.action}")

    def _workspace_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self._require_policy("workspace.read")
        relative = self._relative_path(params)
        path = self.workspace.resolve(relative)
        if not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        if size > MAX_WORKSPACE_READ_BYTES:
            raise ControlActionPreconditionError("file exceeds workspace.read size limit")
        data = path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        stat = path.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        try:
            content = data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            content = base64.b64encode(data).decode("ascii")
            encoding = "base64"
        self.audit_log.append(
            action="workspace.read",
            project_id=self.workspace.project_id,
            outcome="ok",
            path=relative,
            size=len(data),
            sha256=sha256,
        )
        return {
            "ok": True,
            "path": relative,
            "encoding": encoding,
            "content": content,
            "size": len(data),
            "sha256": sha256,
            "modified_utc": modified,
        }

    def _workspace_write(
        self,
        params: Mapping[str, Any],
        *,
        explicitly_approved: bool,
    ) -> dict[str, Any]:
        relative = self._relative_path(params)
        self._reject_protected_write_path(relative)
        content = params.get("content")
        if not isinstance(content, str):
            raise ControlActionPreconditionError("workspace.write content must be UTF-8 text")
        mode = params.get("mode", "create")
        if mode not in {"create", "replace"}:
            raise ControlActionPreconditionError("workspace.write mode must be create or replace")
        data = content.encode("utf-8")
        if len(data) > MAX_WORKSPACE_WRITE_BYTES:
            raise ControlActionPreconditionError("workspace.write content exceeds size limit")

        destructive = mode == "replace"
        self._require_policy(
            "workspace.write",
            destructive=destructive,
            explicitly_approved=explicitly_approved,
        )
        target = self.workspace.resolve(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Re-resolve after parent creation so a pre-existing symlink/junction
        # cannot silently move the write outside the workspace.
        target = self.workspace.resolve(relative)

        if mode == "create":
            try:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError as exc:
                raise ControlActionPreconditionError(
                    "create mode refuses to overwrite an existing file"
                ) from exc
            try:
                with os.fdopen(fd, "wb", closefd=True) as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                # A failed initial create may leave a partial managed file. Do
                # not auto-delete it here; surface the ambiguity for operator/
                # reconcile handling rather than hiding a side effect.
                raise
        else:
            if not target.is_file():
                raise ControlActionPreconditionError("replace mode requires an existing file")
            expected = params.get("expected_sha256")
            if not isinstance(expected, str) or len(expected) != 64:
                raise ControlActionPreconditionError(
                    "replace mode requires expected_sha256 precondition"
                )
            try:
                int(expected, 16)
            except ValueError as exc:
                raise ControlActionPreconditionError(
                    "expected_sha256 must be hexadecimal"
                ) from exc
            before = hashlib.sha256(target.read_bytes()).hexdigest()
            if before.lower() != expected.lower():
                raise ControlActionPreconditionError(
                    "existing file SHA-256 does not match replace precondition"
                )
            with NamedTemporaryFile(
                "wb",
                dir=target.parent,
                prefix=target.name + ".hms-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                temp_path = Path(handle.name)
            try:
                # Re-check immediately before atomic replacement. The workspace
                # ACL makes concurrent untrusted mutation unlikely, but this
                # second hash still turns ordinary lost-update races into a deny.
                current = hashlib.sha256(target.read_bytes()).hexdigest()
                if current.lower() != expected.lower():
                    raise ControlActionPreconditionError(
                        "existing file changed during replace preparation"
                    )
                os.replace(temp_path, target)
            finally:
                temp_path.unlink(missing_ok=True)

        result_data = target.read_bytes()
        sha256 = hashlib.sha256(result_data).hexdigest()
        stat = target.stat()
        modified = datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
        self.audit_log.append(
            action="workspace.write",
            project_id=self.workspace.project_id,
            outcome="ok",
            path=relative,
            mode=mode,
            size=len(result_data),
            sha256=sha256,
        )
        return {
            "ok": True,
            "path": relative,
            "mode": mode,
            "size": len(result_data),
            "sha256": sha256,
            "modified_utc": modified,
        }

    def _process_test(self, params: Mapping[str, Any]) -> dict[str, Any]:
        target_raw = params.get("target", ".")
        if not isinstance(target_raw, str) or not target_raw.strip():
            raise ControlActionPreconditionError("process.test target must be a string")
        target = self.workspace.resolve(target_raw)
        try:
            relative_target = str(target.relative_to(self.workspace.root)) or "."
        except ValueError as exc:
            raise ControlActionPreconditionError("test target escapes workspace") from exc

        argv = [self.python_executable, "-m", "pytest", relative_target, "-q"]
        if params.get("fail_fast") is True:
            argv.append("-x")
        maxfail = params.get("maxfail")
        if maxfail is not None:
            maxfail_text = str(maxfail)
            if not _SAFE_MAXFAIL.fullmatch(maxfail_text):
                raise ControlActionPreconditionError("maxfail must be an integer from 1 to 999")
            argv.append(f"--maxfail={maxfail_text}")

        timeout = params.get("timeout_seconds", 120)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not (1 <= timeout <= 600):
            raise ControlActionPreconditionError("timeout_seconds must be from 1 to 600")

        result = run_command(
            self.workspace,
            argv,
            capability="process.test",
            audit_log=self.audit_log,
            timeout_seconds=float(timeout),
        )
        response = self._command_response(result)
        response["argv"] = list(result.argv)
        return response

    def _git_status(self) -> dict[str, Any]:
        result = run_command(
            self.workspace,
            ["git", "status", "--short", "--branch", "--untracked-files=all"],
            capability="git.status",
            audit_log=self.audit_log,
            timeout_seconds=30,
        )
        return self._command_response(result)

    def _audit_read(self, params: Mapping[str, Any]) -> dict[str, Any]:
        self._require_policy("audit.read")
        limit = params.get("limit", 20)
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= MAX_AUDIT_EVENTS):
            raise ControlActionPreconditionError(
                f"audit.read limit must be from 1 to {MAX_AUDIT_EVENTS}"
            )
        if not self.audit_log.path.exists():
            return {"ok": True, "events": []}
        lines = self.audit_log.path.read_text(encoding="utf-8").splitlines()
        events: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ControlActionError("audit log contains invalid JSON") from exc
            if not isinstance(event, dict):
                raise ControlActionError("audit log event must be an object")
            events.append(event)
        return {"ok": True, "events": events}
