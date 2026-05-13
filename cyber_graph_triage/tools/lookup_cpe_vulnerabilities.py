from __future__ import annotations

from pathlib import Path
from typing import Any

from ..neo4j_client import Neo4jClient

_CYPHER = (
    Path(__file__).parent.parent / "cypher" / "lookup_cpe_vulnerabilities_graphker.cypher"
).read_text()


def lookup_cpe_vulnerabilities(client: Neo4jClient, keyword: str) -> list[dict[str, Any]]:
    keyword = keyword.strip()
    try:
        rows = client.run(_CYPHER, keyword=keyword)
    except RuntimeError as exc:
        return [{"error": str(exc), "keyword": keyword}]

    results = []
    for row in rows:
        score = row.get("score")
        results.append(
            {
                "cve": row.get("cve"),
                "cpe": row.get("cpe"),
                "vulnerable": row.get("vulnerable"),
                "score": float(score) if score is not None else None,
                "severity": row.get("severity"),
                "cwes": [c for c in (row.get("cwes") or []) if c],
            }
        )
    return results
