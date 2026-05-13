from __future__ import annotations

from pathlib import Path
from typing import Any

from ..neo4j_client import Neo4jClient

_CYPHER_TEMPLATE = """\
MATCH (cve:CVE)-[a:applicableIn]->(cpe:CPE)
WHERE toLower(cpe.uri) CONTAINS toLower($keyword)
OPTIONAL MATCH (cve)-[:Problem_Type]->(cwe:CWE)
OPTIONAL MATCH (cve)-[:CVSS3_Impact]->(cvss3:CVSS_3)
RETURN
  cve.Name AS cve,
  cpe.uri AS cpe,
  a.Vulnerable AS vulnerable,
  cvss3.Base_Score AS score,
  cvss3.Base_Severity AS severity,
  collect(DISTINCT cwe.Name) AS cwes
ORDER BY score DESC
LIMIT $limit
"""

_MIN_KEYWORD_LEN = 3
_DEFAULT_LIMIT = 100


def lookup_cpe_vulnerabilities(
    client: Neo4jClient,
    keyword: str,
    limit: int = _DEFAULT_LIMIT,
) -> dict[str, Any]:
    keyword = keyword.strip()

    if len(keyword) < _MIN_KEYWORD_LEN:
        return {
            "keyword": keyword,
            "error": (
                f"Keyword too short (minimum {_MIN_KEYWORD_LEN} characters). "
                "A short keyword like 'php' or 'cisco' may match thousands of CPEs. "
                "Use a more specific term, e.g. 'cisco:ios_xr' or 'apache:struts'."
            ),
            "results": [],
            "count": 0,
            "truncated": False,
        }

    try:
        rows = client.run(_CYPHER_TEMPLATE, keyword=keyword, limit=limit + 1)
    except RuntimeError as exc:
        return {
            "keyword": keyword,
            "error": str(exc),
            "results": [],
            "count": 0,
            "truncated": False,
        }

    truncated = len(rows) > limit
    rows = rows[:limit]

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

    return {
        "keyword": keyword,
        "count": len(results),
        "truncated": truncated,
        "warning": (
            "Results are based on substring match of CPE URI strings, "
            "not a precise CPE inventory match. Validate affected assets separately."
        ),
        "results": results,
    }
