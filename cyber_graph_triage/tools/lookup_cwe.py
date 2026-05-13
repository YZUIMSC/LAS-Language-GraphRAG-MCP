from __future__ import annotations

from pathlib import Path
from typing import Any

from ..neo4j_client import Neo4jClient

_CYPHER = (Path(__file__).parent.parent / "cypher" / "lookup_cwe_graphker.cypher").read_text()


def lookup_cwe(client: Neo4jClient, cwe_id: str) -> dict[str, Any]:
    cwe_id = cwe_id.upper().strip()
    try:
        rows = client.run(_CYPHER, cwe_id=cwe_id)
    except RuntimeError as exc:
        return {"found": False, "cwe": cwe_id, "error": str(exc)}

    if not rows:
        return {"found": False, "cwe": cwe_id}

    row = rows[0]
    return {
        "found": True,
        "cwe": row.get("cwe") or cwe_id,
        "name": row.get("name"),
        "description": row.get("description"),
        "abstraction": row.get("abstraction"),
        "structure": row.get("structure"),
        "status": row.get("status"),
        "related_cwes": _clean_related(row.get("related_cwes", [])),
        "capecs": _clean_capecs(row.get("capecs", [])),
        "mitigations": [m for m in row.get("mitigations", []) if m],
        "consequences": _flatten_consequences(row.get("consequences", [])),
    }


def _clean_related(lst: list) -> list[dict]:
    seen: set = set()
    out = []
    for item in lst:
        if not isinstance(item, dict):
            continue
        target = item.get("target")
        nature = item.get("nature")
        if not target:
            continue
        key = (nature, target)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _flatten_consequences(lst: list) -> list[str]:
    out = []
    for item in lst:
        if not item:
            continue
        if isinstance(item, list):
            out.extend(str(x) for x in item if x)
        else:
            out.append(str(item))
    return sorted(set(out))


def _clean_capecs(lst: list) -> list[dict]:
    seen: set = set()
    out = []
    for item in lst:
        if not isinstance(item, dict):
            continue
        capec = item.get("capec")
        if not capec or capec in seen:
            continue
        seen.add(capec)
        out.append(item)
    return out
