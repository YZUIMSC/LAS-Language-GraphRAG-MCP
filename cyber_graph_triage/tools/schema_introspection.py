from __future__ import annotations

from typing import Any

from ..neo4j_client import Neo4jClient

_COUNT_QUERIES: list[tuple[str, str]] = [
    ("node_counts.CVE", "MATCH (n:CVE) RETURN count(n) AS c"),
    ("node_counts.CWE", "MATCH (n:CWE) RETURN count(n) AS c"),
    ("node_counts.CAPEC", "MATCH (n:CAPEC) RETURN count(n) AS c"),
    ("node_counts.ATTACK", "MATCH (n:ATTACK) RETURN count(n) AS c"),
    ("node_counts.CPE", "MATCH (n:CPE) RETURN count(n) AS c"),
    ("edge_counts.CVE_to_CWE", "MATCH (:CVE)-[:Problem_Type]->(:CWE) RETURN count(*) AS c"),
    ("edge_counts.CWE_to_CAPEC", "MATCH (:CWE)-[:RelatedAttackPattern]->(:CAPEC) RETURN count(*) AS c"),
    ("edge_counts.CAPEC_to_ATTACK", "MATCH (:CAPEC)-[:Mapped_Attack]->(:ATTACK) RETURN count(*) AS c"),
    ("edge_counts.CVE_to_CPE", "MATCH (:CVE)-[:applicableIn]->(:CPE) RETURN count(*) AS c"),
]


def schema_introspection(client: Neo4jClient) -> dict[str, Any]:
    try:
        label_rows = client.run("CALL db.labels()")
        labels = sorted(r.get("label") for r in label_rows if r.get("label"))
    except RuntimeError as exc:
        return {"error": str(exc)}

    try:
        rel_rows = client.run("CALL db.relationshipTypes()")
        relationship_types = sorted(r.get("relationshipType") for r in rel_rows if r.get("relationshipType"))
    except RuntimeError as exc:
        return {"error": str(exc), "labels": labels}

    node_counts: dict[str, int] = {}
    edge_counts: dict[str, int] = {}
    health_warnings: list[str] = []

    for key, cypher in _COUNT_QUERIES:
        section, name = key.split(".", 1)
        target = node_counts if section == "node_counts" else edge_counts
        try:
            rows = client.run(cypher)
            target[name] = rows[0]["c"] if rows else 0
        except Exception:
            target[name] = -1
            health_warnings.append(f"Could not count {key} (label/relationship may not exist)")

    if node_counts.get("CVE", 0) == 0:
        health_warnings.append("No CVE nodes found — graph may be empty or not yet imported")
    if edge_counts.get("CAPEC_to_ATTACK", 0) == 0:
        health_warnings.append("No CAPEC→ATTACK edges — ATT&CK trace will return no results")

    return {
        "labels": labels,
        "relationship_types": relationship_types,
        "node_counts": node_counts,
        "edge_counts": edge_counts,
        "health_warnings": health_warnings,
    }
