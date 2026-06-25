from __future__ import annotations

import re
from typing import Any

from ..neo4j_client import Neo4jClient

_MAX_ROWS = 500

# Guard against write/DDL operations at the tool layer.
# The underlying account is read-only, but this gives AI agents an explicit,
# early signal rather than a confusing Forbidden error from the database.
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
    """Execute a read-only Cypher query and return structured results or a structured error.

    Never raises — all failures are returned as ``{"error": ..., "error_type": ..., "query": ...}``.
    Refuses queries that contain write/DDL keywords.
    Results are capped at min(limit, 500) rows using driver-level lazy fetching.
    """
    query = query.strip()
    if not query:
        return {"error": "query must not be empty", "error_type": "EmptyQuery", "query": query}

    m = _WRITE_PATTERN.search(query)
    if m:
        return {
            "error": (
                f"Write operation '{m.group(0).strip()}' is not allowed. "
                "This tool is read-only. Use MATCH / RETURN / CALL (non-writing procedures) only."
            ),
            "error_type": "WriteOperationNotAllowed",
            "query": query,
        }

    effective_limit = min(max(1, limit), _MAX_ROWS)

    try:
        # Fetch one extra record to detect truncation without materialising the full result set.
        # The driver streams lazily so we stop reading after effective_limit + 1 records.
        rows = client.run(query, fetch_limit=effective_limit + 1, **(params or {}))
    except Exception as exc:
        return {
            "error": str(exc),
            "error_type": type(exc).__name__,
            "query": query,
        }

    truncated = len(rows) > effective_limit
    result_rows = rows[:effective_limit]

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
