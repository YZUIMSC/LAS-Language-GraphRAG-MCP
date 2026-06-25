from __future__ import annotations

import re
from typing import Any

from ..neo4j_client import Neo4jClient

_MAX_ROWS = 500

# Simple guard against write/DDL operations
_WRITE_PATTERN = re.compile(
    r"\b(CREATE|MERGE|SET\s|DELETE|DETACH|REMOVE|DROP|LOAD\s+CSV|CALL\s*\{)\b",
    re.IGNORECASE,
)


def execute_cypher(
    client: Neo4jClient,
    query: str,
    params: dict[str, Any] | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """Execute a read-only Cypher query and return results.

    Refuses queries that contain write/DDL keywords.
    Results are capped at min(limit, 500) rows.
    """
    query = query.strip()
    if not query:
        return {"error": "query must not be empty"}

    m = _WRITE_PATTERN.search(query)
    if m:
        return {
            "error": f"Write operation '{m.group(0).strip()}' is not allowed. "
                     "This tool is read-only. Use MATCH / RETURN / CALL (non-writing procedures) only."
        }

    effective_limit = min(max(1, limit), _MAX_ROWS)

    try:
        rows = client.run(query, **(params or {}))
    except RuntimeError as exc:
        return {"error": str(exc), "query": query}

    truncated = len(rows) > effective_limit
    result_rows = rows[:effective_limit]

    # Convert any non-JSON-serialisable Neo4j types to strings
    serialised = [_serialise_row(r) for r in result_rows]

    return {
        "rows": serialised,
        "count": len(serialised),
        "truncated": truncated,
        "truncated_at": effective_limit if truncated else None,
    }


def _serialise_row(row: dict[str, Any]) -> dict[str, Any]:
    return {k: _serialise_value(v) for k, v in row.items()}


def _serialise_value(v: Any) -> Any:
    if v is None or isinstance(v, (bool, int, float, str)):
        return v
    if isinstance(v, list):
        return [_serialise_value(x) for x in v]
    if isinstance(v, dict):
        return {k2: _serialise_value(v2) for k2, v2 in v.items()}
    # Neo4j Node / Relationship / Path objects → stringify
    return str(v)
