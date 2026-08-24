from __future__ import annotations

from pathlib import Path

import pytest

from hms_gpt_vps.agent_service_runtime_config import (
    AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
    AgentServiceRuntimeConfig,
)
from hms_gpt_vps.agent_windows_identity import (
    IDENTITY_FAILURE_ADMINISTRATORS_PRESENT,
    IDENTITY_FAILURE_NOT_LOCAL_SERVICE,
    IDENTITY_FAILURE_SERVICE_SID_ABSENT,
    LOCAL_SERVICE_SID,
    AgentWindowsTokenSnapshot,
    validate_agent_service_token,
)
from hms_gpt_vps.agent_windows_service_host import (
    ERROR_SERVICE_SPECIFIC_ERROR,
    SERVICE_START_PENDING,
    SERVICE_STOPPED,
    AgentWindowsServiceHost,
)


class FakeBackend:
    def __init__(self) -> None:
        self.statuses = []

    def run_dispatcher(self, _service_name, service_main):  # type: ignore[no-untyped-def]
        service_main()

    def register_control_handler(self, _service_name, _handler):  # type: ignore[no-untyped-def]
        return 123

    def set_service_status(self, handle, status):  # type: ignore[no-untyped-def]
        assert handle == 123
        self.statuses.append(status)


def _config(tmp_path: Path) -> AgentServiceRuntimeConfig:
    return AgentServiceRuntimeConfig(
        schema_version=AGENT_SERVICE_RUNTIME_SCHEMA_VERSION,
        instance_id="identity-code-test",
        project_id="project",
        bridge_origin="https://bridge.example",
        workspace_root=str((tmp_path / "workspace").resolve()),
        state_root=str((tmp_path / "state").resolve()),
        python_executable=str((tmp_path / "python.exe").resolve()),
        git_executable=str((tmp_path / "git.exe").resolve()),
        health_port=8765,
    )


@pytest.mark.parametrize(
    ("snapshot", "expected_code"),
    [
        (
            AgentWindowsTokenSnapshot(
                user_sid="S-1-5-18",
                service_sid_present=True,
                administrators_sid_present=False,
                elevated=False,
            ),
            IDENTITY_FAILURE_NOT_LOCAL_SERVICE,
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_present=False,
                administrators_sid_present=False,
                elevated=False,
            ),
            IDENTITY_FAILURE_SERVICE_SID_ABSENT,
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_present=True,
                administrators_sid_present=True,
                elevated=False,
            ),
            IDENTITY_FAILURE_ADMINISTRATORS_PRESENT,
        ),
        (
            AgentWindowsTokenSnapshot(
                user_sid=LOCAL_SERVICE_SID,
                service_sid_present=True,
                administrators_sid_present=True,
                elevated=True,
            ),
            IDENTITY_FAILURE_ADMINISTRATORS_PRESENT,
        ),
    ],
)
def test_identity_validation_failure_is_bounded_to_safe_scm_subcode(
    tmp_path: Path,
    snapshot: AgentWindowsTokenSnapshot,
    expected_code: int,
) -> None:
    backend = FakeBackend()

    def identity_probe():  # type: ignore[no-untyped-def]
        return validate_agent_service_token(snapshot)

    AgentWindowsServiceHost(
        backend,
        identity_probe=identity_probe,
        config_loader=lambda: _config(tmp_path),
        runtime_factory=lambda *_args: pytest.fail("runtime must not be constructed"),
    ).run()

    assert [status.current_state for status in backend.statuses] == [
        SERVICE_START_PENDING,
        SERVICE_STOPPED,
    ]
    failed = backend.statuses[-1]
    assert failed.win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR
    assert failed.service_specific_exit_code == expected_code


def test_token_elevation_flag_cannot_create_an_identity_failure_code() -> None:
    identity = validate_agent_service_token(
        AgentWindowsTokenSnapshot(
            user_sid=LOCAL_SERVICE_SID,
            service_sid_present=True,
            administrators_sid_present=False,
            elevated=True,
        )
    )

    assert identity.privilege == "non-admin"


def test_untrusted_identity_exception_code_cannot_escape_bounded_mapping(tmp_path: Path) -> None:
    backend = FakeBackend()

    class MaliciousIdentityError(PermissionError):
        safe_service_code = 424242

    AgentWindowsServiceHost(
        backend,
        identity_probe=lambda: (_ for _ in ()).throw(MaliciousIdentityError("hidden")),
        config_loader=lambda: _config(tmp_path),
        runtime_factory=lambda *_args: pytest.fail("runtime must not be constructed"),
    ).run()

    assert backend.statuses[-1].service_specific_exit_code == 10
