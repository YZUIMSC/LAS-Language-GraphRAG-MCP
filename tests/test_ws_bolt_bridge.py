from __future__ import annotations

import asyncio

import pytest

from cyber_graph_triage.ws_bolt_bridge import (
    parse_websocket_target,
    read_ws_frame,
    write_ws_frame,
)


def test_parse_websocket_target_defaults_wss_port_and_path() -> None:
    target = parse_websocket_target("wss://graphker.lab.114514.my.id")

    assert target.scheme == "wss"
    assert target.host == "graphker.lab.114514.my.id"
    assert target.port == 443
    assert target.path == "/"


def test_parse_websocket_target_preserves_port_path_and_query() -> None:
    target = parse_websocket_target("ws://example.com:8080/bolt?database=neo4j")

    assert target.scheme == "ws"
    assert target.host == "example.com"
    assert target.port == 8080
    assert target.path == "/bolt?database=neo4j"


def test_parse_websocket_target_rejects_non_websocket_scheme() -> None:
    with pytest.raises(ValueError, match="ws:// or wss://"):
        parse_websocket_target("bolt://example.com:7687")


@pytest.mark.asyncio
async def test_write_and_read_masked_binary_frame() -> None:
    async def handle_client(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        opcode, payload, fin = await read_ws_frame(reader)
        assert opcode == 0x2
        assert payload == b"\x60\x60\xb0\x17"
        assert fin is True
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await write_ws_frame(writer, 0x2, b"\x60\x60\xb0\x17")
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()
