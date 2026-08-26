from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import subprocess

import pytest

import hms_gpt_vps.secure_mcp_tunnel_runtime as module
import hms_gpt_vps.secure_mcp_tunnel_health as health
from hms_gpt_vps.bridge_service_secret_storage import BridgeServiceSecretStorageConfig


SID = "S-1-5-80-1-2-3-4-5"
TUNNEL_ID = "tunnel_" + "a" * 32


class Stop:
    def __init__(self):
        self.set = False
        self.waits = 0

    def is_set(self) -> bool:
        return self.set

    def wait(self, timeout=None) -> bool:
        self.waits += 1
        return self.set


class FakeProcess:
    def __init__(self, pid=4242):
        self.pid = pid
        self.returncode = None
        self.terminated = 0
        self.killed = 0
        self.wait_calls = 0
        self.timeout_once = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated += 1

    def kill(self):
        self.killed += 1
        self.returncode = -9

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.timeout_once and self.killed == 0:
            raise subprocess.TimeoutExpired("tunnel", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakePackage:
    def __init__(self, install_root: Path, executable_path: Path):
        self.install_root = install_root
        self.executable_path = executable_path

    def validate(self):
        return None


def make_runtime(monkeypatch, tmp_path, *, responses=None, process=None):
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    install_root = tmp_path / "package"
    install_root.mkdir()
    executable = install_root / "tunnel-client-runtime.exe"
    executable.write_bytes(b"exe")
    secret_parent = tmp_path / "secrets"
    secret_parent.mkdir()
    secret = BridgeServiceSecretStorageConfig(secret_parent / "service-runtime", SID)
    package = FakePackage(install_root, executable)

    monkeypatch.setattr(module, "DEFAULT_BRIDGE_RUNTIME_ROOT", runtime_root)
    monkeypatch.setattr(module, "TunnelRuntimePackageConfig", FakePackage)
    monkeypatch.setattr(module, "prove_hms_bridge_runtime_identity", lambda sid: {"sid": sid})
    monkeypatch.setattr(module, "prove_bridge_service_secret_storage", lambda *a, **k: {"ready": True})
    monkeypatch.setattr(
        module,
        "prove_installed_tunnel_runtime",
        lambda *a, **k: SimpleNamespace(
            executable_path=str(executable),
            executable_sha256="1" * 64,
        ),
    )

    class KeyStore:
        def __init__(self, config):
            pass

        def load(self):
            return "restricted_runtime_key"

    monkeypatch.setattr(module, "TunnelRuntimeApiKeyStore", KeyStore)

    captured = {}
    fake_process = process or FakeProcess()

    def factory(argv, environment, cwd):
        captured["argv"] = tuple(argv)
        captured["environment"] = dict(environment)
        captured["cwd"] = cwd
        health_path = Path(argv[argv.index("--health.url-file") + 1])
        health_path.write_text("http://127.0.0.1:54321", encoding="ascii")
        return fake_process

    queue = list(responses or [health.TunnelHealthResponse(200, b"ready", "text/plain")])

    def probe(url, timeout):
        captured.setdefault("probes", []).append(url)
        if len(queue) > 1:
            return queue.pop(0)
        return queue[0]

    config = module.SecureMcpTunnelRuntimeConfig(
        expected_service_sid=SID,
        secret_storage=secret,
        tunnel_id=TUNNEL_ID,
        package=package,
        runtime_root=runtime_root,
        probe_interval_seconds=0.02,
        steady_probe_interval_seconds=0.10,
    )
    runtime = module.SecureMcpTunnelRuntime(
        config,
        process_factory=factory,
        health_probe=probe,
    )
    return runtime, fake_process, captured


def test_health_url_handshake_requires_exact_loopback(tmp_path):
    path = tmp_path / "health"
    path.write_text("http://127.0.0.1:54321", encoding="ascii")
    assert health.parse_health_base_url(path) == "http://127.0.0.1:54321"
    for value in (
        "http://localhost:54321",
        "https://127.0.0.1:54321",
        "http://u:p@127.0.0.1:54321",
        "http://127.0.0.1:54321/other",
        "http://127.0.0.1:54321?q=1",
    ):
        path.write_text(value, encoding="ascii")
        with pytest.raises(health.TunnelHealthError):
            health.parse_health_base_url(path)


def test_readiness_accepts_upstream_ready_forms_only():
    assert health.readiness_response_is_ready(
        health.TunnelHealthResponse(200, b"ready", "text/plain")
    )
    assert health.readiness_response_is_ready(
        health.TunnelHealthResponse(
            200,
            b"ready (mcp initialize requires auth: 401)",
            "text/plain; charset=utf-8",
        )
    )
    assert not health.readiness_response_is_ready(
        health.TunnelHealthResponse(503, b"mcp startup probe pending", "text/plain")
    )
    assert not health.readiness_response_is_ready(
        health.TunnelHealthResponse(200, b"not-ready", "text/plain")
    )
    assert not health.readiness_response_is_ready(
        health.TunnelHealthResponse(
            200,
            b"ready (mcp startup probe timed out: context deadline exceeded)",
            "text/plain",
        )
    )


def test_start_waits_through_503_then_commits_ready(monkeypatch, tmp_path):
    runtime, process, captured = make_runtime(
        monkeypatch,
        tmp_path,
        responses=[
            health.TunnelHealthResponse(503, b"mcp startup probe pending", "text/plain"),
            health.TunnelHealthResponse(200, b"ready", "text/plain"),
        ],
    )
    stop = Stop()
    assert runtime.start(stop) is True
    evidence = runtime.evidence()
    assert evidence.ready is True
    assert evidence.process_id == process.pid
    assert evidence.readiness_url == "http://127.0.0.1:54321/readyz"
    assert evidence.restart_policy == "fail-closed-to-HMSBridge-SCM"
    argv_text = " ".join(captured["argv"])
    assert "restricted_runtime_key" not in argv_text
    assert "--health.listen-addr 127.0.0.1:0" in argv_text
    assert "--mcp.startup-wait-timeout 30s" in argv_text
    assert captured["environment"]["CONTROL_PLANE_API_KEY"] == "restricted_runtime_key"
    assert captured["environment"]["MCP_SERVER_URL"] == "http://127.0.0.1:8765/mcp"
    runtime.shutdown()
    assert process.terminated == 1


def test_spawn_failure_scrubs_secret_and_cleans_handshake(monkeypatch, tmp_path):
    runtime, _, captured = make_runtime(monkeypatch, tmp_path)
    health_paths = []

    def failing_factory(argv, environment, cwd):
        captured["live_environment"] = environment
        health_paths.append(Path(argv[argv.index("--health.url-file") + 1]))
        raise OSError("spawn failed")

    runtime.process_factory = failing_factory
    with pytest.raises(OSError, match="spawn failed"):
        runtime.start(Stop())
    assert captured["live_environment"]["CONTROL_PLANE_API_KEY"] == ""
    assert health_paths and not health_paths[0].exists()
    assert not health_paths[0].parent.exists()


def test_start_fails_closed_on_non_503_non_200_readiness(monkeypatch, tmp_path):
    runtime, process, _ = make_runtime(
        monkeypatch,
        tmp_path,
        responses=[health.TunnelHealthResponse(401, b"unauthorized", "text/plain")],
    )
    with pytest.raises(module.SecureMcpTunnelRuntimeError, match="HTTP 401"):
        runtime.start(Stop())
    assert process.terminated == 1
    assert runtime.ready is False


def test_wait_fails_closed_on_unexpected_child_exit(monkeypatch, tmp_path):
    runtime, process, _ = make_runtime(monkeypatch, tmp_path)
    stop = Stop()
    assert runtime.start(stop) is True
    process.returncode = 9
    with pytest.raises(module.SecureMcpTunnelRuntimeError, match="exited unexpectedly"):
        runtime.wait(stop)
    runtime.shutdown()


def test_assert_healthy_reprobes_ready_runtime(monkeypatch, tmp_path):
    runtime, _, captured = make_runtime(
        monkeypatch,
        tmp_path,
        responses=[
            health.TunnelHealthResponse(200, b"ready", "text/plain"),
            health.TunnelHealthResponse(200, b"ready", "text/plain"),
        ],
    )
    assert runtime.start(Stop()) is True
    runtime.assert_healthy()
    assert captured["probes"] == [
        "http://127.0.0.1:54321/readyz",
        "http://127.0.0.1:54321/readyz",
    ]
    runtime.shutdown()


def test_assert_healthy_fails_closed_on_child_exit(monkeypatch, tmp_path):
    runtime, process, _ = make_runtime(monkeypatch, tmp_path)
    assert runtime.start(Stop()) is True
    process.returncode = 23
    with pytest.raises(
        module.SecureMcpTunnelRuntimeError,
        match="exited unexpectedly with code 23",
    ):
        runtime.assert_healthy()
    runtime.shutdown()


def test_assert_healthy_rejects_degraded_readiness(monkeypatch, tmp_path):
    runtime, _, _ = make_runtime(
        monkeypatch,
        tmp_path,
        responses=[
            health.TunnelHealthResponse(200, b"ready", "text/plain"),
            health.TunnelHealthResponse(503, b"mcp startup probe failed", "text/plain"),
        ],
    )
    assert runtime.start(Stop()) is True
    with pytest.raises(module.SecureMcpTunnelRuntimeError, match="HTTP 503"):
        runtime.assert_healthy()
    runtime.shutdown()


def test_shutdown_escalates_terminate_to_kill_after_bound(monkeypatch, tmp_path):
    process = FakeProcess()
    process.timeout_once = True
    runtime, _, _ = make_runtime(monkeypatch, tmp_path, process=process)
    assert runtime.start(Stop()) is True
    runtime.shutdown()
    assert process.terminated == 1
    assert process.killed == 1
    assert process.wait_calls == 2


def test_run_contains_no_blind_child_restart_loop():
    import inspect

    source = inspect.getsource(module.SecureMcpTunnelRuntime.run)
    assert "while" not in source
    assert "self.start" in source
    assert "self.wait" in source
    assert "self.shutdown" in source
