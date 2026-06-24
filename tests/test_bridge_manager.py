from __future__ import annotations

import os

from cyber_graph_triage import bridge_manager


class FakeProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def wait(self, timeout: float | None = None) -> int:
        return 0

    def kill(self) -> None:
        self.killed = True


def test_auto_start_ws_bridge_from_env_is_noop_without_target(monkeypatch) -> None:
    monkeypatch.delenv("NEO4J_WS_BRIDGE_TARGET", raising=False)
    monkeypatch.delenv("NEO4J_URI", raising=False)

    with bridge_manager.auto_start_ws_bridge_from_env():
        assert "NEO4J_URI" not in os.environ


def test_auto_start_ws_bridge_from_env_sets_local_uri_and_stops_process(
    monkeypatch,
) -> None:
    fake_process = FakeProcess()
    popen_args: list[list[str]] = []

    def fake_popen(args: list[str]) -> FakeProcess:
        popen_args.append(args)
        return fake_process

    monkeypatch.setenv("NEO4J_WS_BRIDGE_TARGET", "wss://graph.example.com/")
    monkeypatch.setenv("NEO4J_WS_BRIDGE_LISTEN_PORT", "27687")
    monkeypatch.setattr(bridge_manager.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(bridge_manager, "_wait_for_bridge", lambda host, port: None)

    with bridge_manager.auto_start_ws_bridge_from_env():
        assert os.environ["NEO4J_URI"] == "bolt://127.0.0.1:27687"

    assert fake_process.terminated is True
    assert fake_process.killed is False
    assert popen_args[0][-2:] == ["--target", "wss://graph.example.com/"]
