from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env", override=False)

SUPPORTED_NEO4J_URI_SCHEMES = (
    "bolt",
    "bolt+s",
    "bolt+ssc",
    "neo4j",
    "neo4j+s",
    "neo4j+ssc",
)


def validate_neo4j_uri(uri: str) -> str:
    scheme = urlparse(uri).scheme
    if scheme not in SUPPORTED_NEO4J_URI_SCHEMES:
        supported = ", ".join(SUPPORTED_NEO4J_URI_SCHEMES)
        raise ValueError(
            "Unsupported NEO4J_URI scheme "
            f"{scheme!r}. The Neo4j Python driver supports only: {supported}. "
            "Direct ws:// or wss:// Bolt-over-WebSocket is not supported by this "
            "server's Python driver. If you need Cloudflare in the path, publish "
            "a TCP service and point NEO4J_URI to a local or direct bolt:// or "
            "neo4j:// endpoint instead."
        )
    return uri


def get_neo4j_config() -> dict[str, str]:
    uri = validate_neo4j_uri(os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    return {
        "uri": uri,
        "user": os.environ.get("NEO4J_USER", "neo4j"),
        "password": os.environ.get("NEO4J_PASSWORD", ""),
        "database": os.environ.get("NEO4J_DATABASE", "neo4j"),
    }
