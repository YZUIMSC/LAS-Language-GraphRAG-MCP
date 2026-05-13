from __future__ import annotations

from pathlib import Path
from typing import Any

from ..neo4j_client import Neo4jClient

_BASE_CYPHER = (
    Path(__file__).parent.parent / "cypher" / "trace_cve_to_attack_graphker.cypher"
).read_text()

# Candidate labels and relationships for ATT&CK nodes
_ATTACK_LABELS = ["ATTACK", "Technique", "ATTACK_Technique", "Attack_Technique"]
_ATTACK_RELS = ["Mapped_Attack", "MAPS_TO_ATTACK", "USES_ATTACK_TECHNIQUE", "mapsToTechnique", "RelatedTechnique"]


def trace_cve_to_attack(client: Neo4jClient, cve_id: str) -> dict[str, Any]:
    cve_id = cve_id.upper().strip()
    try:
        rows = client.run(_BASE_CYPHER, cve_id=cve_id)
    except RuntimeError as exc:
        return {"found": False, "cve": cve_id, "paths": [], "warnings": [str(exc)]}

    if not rows or not rows[0].get("cve"):
        return {"found": False, "cve": cve_id, "paths": [], "warnings": []}

    capec_names = [r["capec"] for r in rows if r.get("capec")]
    paths_base = [
        {
            "cwe": r.get("cwe"),
            "cwe_name": r.get("cwe_name"),
            "capec": r.get("capec"),
            "capec_name": r.get("capec_name"),
        }
        for r in rows
    ]

    warnings: list[str] = []
    attack_map: dict[str, dict] = {}

    if capec_names:
        attack_map = _try_attack_lookup(client, capec_names)
        if not attack_map:
            warnings.append(
                "No ATT&CK mapping found from CAPEC nodes. "
                "Check technique labels and relationship names."
            )

    paths = []
    for p in paths_base:
        capec = p.get("capec")
        entry: dict[str, Any] = dict(p)
        if capec and capec in attack_map:
            entry["attack"] = attack_map[capec]
        else:
            entry["attack"] = None
        paths.append(entry)

    return {
        "found": True,
        "cve": cve_id,
        "paths": paths,
        "warnings": warnings,
    }


def _try_attack_lookup(client: Neo4jClient, capec_names: list[str]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for label in _ATTACK_LABELS:
        for rel in _ATTACK_RELS:
            cypher = (
                f"MATCH (capec:CAPEC)-[r:{rel}]->(t:{label}) "
                "WHERE capec.Name IN $capec_names "
                "RETURN capec.Name AS capec, "
                "coalesce(t.ID, t.Name) AS tech_id, "
                "coalesce(t.Name, t.TechniqueName, t.Extended_Name) AS tech_name, "
                f"'{rel}' AS relation"
            )
            try:
                rows = client.run(cypher, capec_names=capec_names)
                for row in rows:
                    capec = row.get("capec")
                    if capec and capec not in result:
                        result[capec] = {
                            "id": row.get("tech_id"),
                            "name": row.get("tech_name"),
                            "relation": row.get("relation"),
                        }
            except Exception:
                continue
    return result
