from __future__ import annotations

from typing import Any

from ..neo4j_client import Neo4jClient

_REL_PATTERN_QUERY = """
MATCH (a)-[r]->(b)
WITH labels(a)[0] AS from_label, type(r) AS rel_type, labels(b)[0] AS to_label
RETURN from_label, rel_type, to_label, count(*) AS cnt
ORDER BY cnt DESC
LIMIT 200
"""


def get_schema(client: Neo4jClient) -> dict[str, Any]:
    """Return a sampled schema view: node labels with observed property keys and
    relationship patterns discovered from the live graph.

    IMPORTANT — this is a best-effort sampling, not an authoritative schema:
    - Property keys are collected by sampling up to 5 nodes per label; sparse
      or rarely-populated properties may not appear.
    - Relationship patterns are sampled from live edges; low-frequency patterns
      may be missing.
    - Multi-label nodes are represented only by their first label in patterns.
    Use as orientation before writing Cypher, not as a guarantee of completeness.
    """
    try:
        label_rows = client.run("CALL db.labels()")
        labels: list[str] = sorted(r["label"] for r in label_rows if r.get("label"))
    except RuntimeError as exc:
        return {"error": str(exc)}

    # Union property keys across up to 5 sampled nodes per label.
    # A single query per label keeps the total query count the same as before
    # while covering more of the property space than a single-node sample.
    node_properties: dict[str, list[str]] = {}
    for label in labels:
        try:
            rows = client.run(
                f"MATCH (n:`{label}`) WITH n LIMIT 5 "
                f"UNWIND keys(n) AS prop RETURN collect(DISTINCT prop) AS props"
            )
            node_properties[label] = sorted(rows[0].get("props") or []) if rows else []
        except Exception:
            node_properties[label] = []

    # Discover relationship patterns by sampling the graph
    rel_patterns: list[dict[str, Any]] = []
    try:
        rows = client.run(_REL_PATTERN_QUERY)
        for row in rows:
            if row.get("from_label") and row.get("rel_type") and row.get("to_label"):
                rel_patterns.append({
                    "from": row["from_label"],
                    "type": row["rel_type"],
                    "to": row["to_label"],
                    "count": row["cnt"],
                })
    except Exception:
        pass

    try:
        rel_type_rows = client.run("CALL db.relationshipTypes()")
        rel_types = [r["relationshipType"] for r in rel_type_rows if r.get("relationshipType")]
    except Exception:
        rel_types = list({p["type"] for p in rel_patterns})

    # Union relationship property keys across up to 5 sampled edges per type.
    rel_properties: dict[str, list[str]] = {}
    for rtype in rel_types:
        try:
            rows = client.run(
                f"MATCH ()-[r:`{rtype}`]->() WITH r LIMIT 5 "
                f"UNWIND keys(r) AS prop RETURN collect(DISTINCT prop) AS props"
            )
            rel_properties[rtype] = sorted(rows[0].get("props") or []) if rows else []
        except Exception:
            rel_properties[rtype] = []

    return {
        "node_labels": labels,
        "node_properties": node_properties,
        "relationship_patterns": rel_patterns,
        "relationship_properties": rel_properties,
        "sampling_note": (
            "sampled: true — property keys and relationship patterns are observed from "
            "live graph samples (up to 5 nodes/edges per type). "
            "Sparse properties and low-frequency relationships may be absent. "
            "All identifiers are case-sensitive in Cypher."
        ),
    }
