from __future__ import annotations

import pytest

from cyber_graph_triage.config import get_neo4j_config, validate_neo4j_uri


def test_validate_neo4j_uri_allows_supported_schemes() -> None:
    assert validate_neo4j_uri("bolt://localhost:7687") == "bolt://localhost:7687"
    assert validate_neo4j_uri("neo4j+s://graph.example.com:7687") == (
        "neo4j+s://graph.example.com:7687"
    )


def test_validate_neo4j_uri_rejects_websocket_schemes() -> None:
    with pytest.raises(ValueError, match="Bolt-over-WebSocket"):
        validate_neo4j_uri("wss://graph.example.com:443")


def test_get_neo4j_config_uses_validated_uri(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEO4J_URI", "bolt+s://graph.example.com:7687")
    cfg = get_neo4j_config()
    assert cfg["uri"] == "bolt+s://graph.example.com:7687"
