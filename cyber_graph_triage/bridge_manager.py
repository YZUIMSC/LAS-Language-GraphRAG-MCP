from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from typing import Iterator


def _is_bridge_enabled() -> bool:
    return (
        bool(os.environ.get("NEO4J_WS_BRIDGE_TARGET"))
        and os.environ.get("NEO4J_WS_BRIDGE_ENABLED", "true").lower() != "false"
    )


def _wait_for_bridge(host: str, port: int, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for Neo4j WebSocket bridge: {last_error}")


@contextmanager
def auto_start_ws_bridge_from_env() -> Iterator[None]:
    if not _is_bridge_enabled():
        yield
        return

    listen_host = os.environ.get("NEO4J_WS_BRIDGE_LISTEN_HOST", "127.0.0.1")
    connect_host = os.environ.get("NEO4J_WS_BRIDGE_CONNECT_HOST", "127.0.0.1")
    listen_port = int(os.environ.get("NEO4J_WS_BRIDGE_LISTEN_PORT", "17687"))
    target = os.environ["NEO4J_WS_BRIDGE_TARGET"]
    os.environ["NEO4J_URI"] = f"bolt://{connect_host}:{listen_port}"

    print(
        f"Starting Neo4j WebSocket bridge at {os.environ['NEO4J_URI']} -> {target}",
        file=sys.stderr,
        flush=True,
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "cyber_graph_triage.ws_bolt_bridge",
            "--listen-host",
            listen_host,
            "--listen-port",
            str(listen_port),
            "--target",
            target,
        ]
    )
    try:
        _wait_for_bridge(connect_host, listen_port)
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
