from __future__ import annotations

from typing import Any

from .config import get_neo4j_config


class Neo4jClient:
    def __init__(self) -> None:
        self._driver = None

    def _ensure_driver(self) -> None:
        if self._driver is not None:
            return
        try:
            from neo4j import GraphDatabase  # type: ignore
        except ImportError as exc:
            raise RuntimeError("neo4j package is not installed.") from exc

        cfg = None
        try:
            cfg = get_neo4j_config()
            self._driver = GraphDatabase.driver(
                cfg["uri"],
                auth=(cfg["user"], cfg["password"]),
            )
            self._driver.verify_connectivity()
        except Exception as exc:
            self._driver = None
            uri = cfg["uri"] if cfg is not None else "<invalid NEO4J_URI>"
            raise RuntimeError(
                f"Cannot connect to Neo4j at {uri}: {exc}"
            ) from exc

    def run(self, query: str, **params: Any) -> list[dict[str, Any]]:
        self._ensure_driver()
        cfg = get_neo4j_config()
        with self._driver.session(database=cfg["database"]) as session:
            result = session.run(query, **params)
            return [dict(record) for record in result]

    def close(self) -> None:
        if self._driver:
            self._driver.close()
            self._driver = None
