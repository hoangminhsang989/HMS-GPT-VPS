from __future__ import annotations

import os
import sys

import pytest

from hms_gpt_vps import agent_windows_service_host as service_host
from hms_gpt_vps import cli


def test_public_service_entrypoint_exists_and_cli_dispatches_to_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    assert callable(service_host.run_hms_agent_windows_service)
    monkeypatch.setattr(
        service_host,
        "run_hms_agent_windows_service",
        lambda: calls.append("service"),
    )
    monkeypatch.setattr(sys, "argv", ["hms-agent", "service"])

    assert cli.main() == 0
    assert calls == ["service"]


@pytest.mark.skipif(os.name != "nt", reason="native Windows callback retention smoke only")
def test_native_backend_retains_callback_lifetime_and_error_state() -> None:
    backend = service_host.NativeWindowsServiceControlBackend()

    assert isinstance(backend._service_main_callbacks, list)
    assert isinstance(backend._handler_callbacks, list)
    assert isinstance(backend._callback_errors, list)
