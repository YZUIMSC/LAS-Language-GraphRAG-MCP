from __future__ import annotations

from pathlib import Path
from typing import Any

from ..neo4j_client import Neo4jClient

_CYPHER = (Path(__file__).parent.parent / "cypher" / "lookup_cve_graphker.cypher").read_text()


def lookup_cve(client: Neo4jClient, cve_id: str) -> dict[str, Any]:
    cve_id = cve_id.upper().strip()
    try:
        rows = client.run(_CYPHER, cve_id=cve_id)
    except RuntimeError as exc:
        return {"found": False, "cve": cve_id, "error": str(exc)}

    if not rows:
        return {"found": False, "cve": cve_id}

    row = rows[0]
    return {
        "found": True,
        "cve": row.get("cve") or cve_id,
        "description": _flatten_str(row.get("description")),
        "published_date": _str(row.get("published_date")),
        "last_modified_date": _str(row.get("last_modified_date")),
        "cwes": _clean_list(row.get("cwes", [])),
        "cvss3": _clean_score_list(row.get("cvss3", [])),
        "cvss2": _clean_score_list(row.get("cvss2", [])),
        "cpes": _clean_list(row.get("cpes", [])),
        "references": _clean_ref_list(row.get("references", [])),
    }


def _str(v: Any) -> str | None:
    return str(v) if v is not None else None


def _flatten_str(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, list):
        return " ".join(str(x) for x in v if x)
    return str(v)


def _clean_list(lst: list) -> list:
    return [x for x in lst if x]


def _clean_score_list(lst: list) -> list[dict]:
    seen: set = set()
    out = []
    for item in lst:
        if not isinstance(item, dict):
            continue
        if not any(item.values()):
            continue
        key = item.get("vector") or item.get("score")
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        out.append({k: (float(v) if k == "score" and v is not None else v) for k, v in item.items()})
    return out


def _clean_ref_list(lst: list) -> list[dict]:
    seen: set = set()
    out = []
    for item in lst:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not url:
            continue
        if url in seen:
            continue
        seen.add(url)
        out.append(item)
    return out
