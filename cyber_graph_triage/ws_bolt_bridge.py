from __future__ import annotations

import argparse
import asyncio
import base64
import sys
import hashlib
import os
import secrets
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env", override=False)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass(frozen=True)
class WebSocketTarget:
    uri: str
    scheme: str
    host: str
    port: int
    path: str


def parse_websocket_target(uri: str) -> WebSocketTarget:
    parsed = urlparse(uri)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("Bridge target must use ws:// or wss://")
    if not parsed.hostname:
        raise ValueError("Bridge target must include a hostname")

    default_port = 443 if parsed.scheme == "wss" else 80
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    return WebSocketTarget(
        uri=uri,
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=parsed.port or default_port,
        path=path,
    )


async def _read_http_response(
    reader: asyncio.StreamReader,
) -> tuple[str, dict[str, str]]:
    raw = await reader.readuntil(b"\r\n\r\n")
    text = raw.decode("iso-8859-1")
    lines = text.split("\r\n")
    status_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.lower()] = value.strip()
    return status_line, headers


async def open_websocket(
    target: WebSocketTarget,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ssl_context = ssl.create_default_context() if target.scheme == "wss" else None
    reader, writer = await asyncio.open_connection(
        target.host,
        target.port,
        ssl=ssl_context,
        server_hostname=target.host if ssl_context else None,
    )

    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    host_header = target.host
    if target.port not in {80, 443}:
        host_header = f"{target.host}:{target.port}"

    request = (
        f"GET {target.path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    writer.write(request.encode("ascii"))
    await writer.drain()

    status_line, headers = await _read_http_response(reader)
    if not status_line.startswith("HTTP/1.1 101") and not status_line.startswith(
        "HTTP/1.0 101"
    ):
        writer.close()
        await writer.wait_closed()
        raise ConnectionError(f"WebSocket upgrade failed: {status_line}")

    expected_accept = base64.b64encode(
        hashlib.sha1(f"{key}{WS_GUID}".encode("ascii")).digest()
    ).decode("ascii")
    if headers.get("sec-websocket-accept") != expected_accept:
        writer.close()
        await writer.wait_closed()
        raise ConnectionError("WebSocket upgrade returned an invalid accept key")

    return reader, writer


async def write_ws_frame(
    writer: asyncio.StreamWriter,
    opcode: int,
    payload: bytes = b"",
    *,
    masked: bool = True,
) -> None:
    first_byte = 0x80 | opcode
    length = len(payload)
    mask_bit = 0x80 if masked else 0

    if length < 126:
        header = struct.pack("!BB", first_byte, mask_bit | length)
    elif length <= 0xFFFF:
        header = struct.pack("!BBH", first_byte, mask_bit | 126, length)
    else:
        header = struct.pack("!BBQ", first_byte, mask_bit | 127, length)

    if masked:
        mask = secrets.token_bytes(4)
        masked_payload = bytes(
            byte ^ mask[index % 4] for index, byte in enumerate(payload)
        )
        writer.write(header + mask + masked_payload)
    else:
        writer.write(header + payload)
    await writer.drain()


async def read_ws_frame(reader: asyncio.StreamReader) -> tuple[int, bytes, bool]:
    first_two = await reader.readexactly(2)
    first_byte, second_byte = first_two
    fin = bool(first_byte & 0x80)
    opcode = first_byte & 0x0F
    masked = bool(second_byte & 0x80)
    length = second_byte & 0x7F

    if length == 126:
        length = struct.unpack("!H", await reader.readexactly(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await reader.readexactly(8))[0]

    mask = await reader.readexactly(4) if masked else b""
    payload = await reader.readexactly(length) if length else b""
    if masked:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))

    return opcode, payload, fin


async def _tcp_to_ws(
    tcp_reader: asyncio.StreamReader,
    ws_writer: asyncio.StreamWriter,
) -> None:
    while data := await tcp_reader.read(65536):
        await write_ws_frame(ws_writer, 0x2, data)
    await write_ws_frame(ws_writer, 0x8)


async def _ws_to_tcp(
    ws_reader: asyncio.StreamReader,
    ws_writer: asyncio.StreamWriter,
    tcp_writer: asyncio.StreamWriter,
) -> None:
    fragmented_payload = bytearray()
    fragmented_opcode: int | None = None

    while True:
        opcode, payload, fin = await read_ws_frame(ws_reader)

        if opcode == 0x8:
            break
        if opcode == 0x9:
            await write_ws_frame(ws_writer, 0xA, payload)
            continue
        if opcode == 0xA:
            continue

        if opcode in {0x1, 0x2}:
            if fin:
                tcp_writer.write(payload)
                await tcp_writer.drain()
                continue
            fragmented_opcode = opcode
            fragmented_payload.extend(payload)
            continue

        if opcode == 0x0 and fragmented_opcode is not None:
            fragmented_payload.extend(payload)
            if fin:
                tcp_writer.write(bytes(fragmented_payload))
                await tcp_writer.drain()
                fragmented_payload.clear()
                fragmented_opcode = None


async def handle_client(
    tcp_reader: asyncio.StreamReader,
    tcp_writer: asyncio.StreamWriter,
    target: WebSocketTarget,
) -> None:
    peer = tcp_writer.get_extra_info("peername")
    ws_writer: asyncio.StreamWriter | None = None
    try:
        ws_reader, ws_writer = await open_websocket(target)
        await asyncio.gather(
            _tcp_to_ws(tcp_reader, ws_writer),
            _ws_to_tcp(ws_reader, ws_writer, tcp_writer),
        )
    except Exception as exc:
        print(f"Bridge connection failed for {peer}: {exc}", file=sys.stderr, flush=True)
    finally:
        tcp_writer.close()
        await tcp_writer.wait_closed()
        if ws_writer is not None:
            ws_writer.close()
            await ws_writer.wait_closed()


async def run_bridge(listen_host: str, listen_port: int, target_uri: str) -> None:
    target = parse_websocket_target(target_uri)
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, target),
        listen_host,
        listen_port,
    )
    addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(
        f"Listening on {addresses}; forwarding Bolt over WebSocket to {target.uri}",
        file=sys.stderr,
        flush=True,
    )
    async with server:
        await server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Expose a local Bolt TCP listener backed by a remote WebSocket endpoint."
    )
    parser.add_argument(
        "--listen-host",
        default=os.environ.get("NEO4J_WS_BRIDGE_LISTEN_HOST", "127.0.0.1"),
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=int(os.environ.get("NEO4J_WS_BRIDGE_LISTEN_PORT", "17687")),
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("NEO4J_WS_BRIDGE_TARGET", ""),
        help="Remote WebSocket endpoint, for example wss://graph.example.com:443/",
    )
    args = parser.parse_args()

    if not args.target:
        raise SystemExit("Missing --target or NEO4J_WS_BRIDGE_TARGET")

    try:
        asyncio.run(run_bridge(args.listen_host, args.listen_port, args.target))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
