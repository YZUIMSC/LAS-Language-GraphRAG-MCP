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
    """Return node labels with their property keys and relationship patterns.

    Designed to give an AI agent enough context to write correct Cypher queries
    against this graph without guessing label names, property keys, or relationship types.
    """
    try:
        label_rows = client.run("CALL db.labels()")
        labels: list[str] = sorted(r["label"] for r in label_rows if r.get("label"))
    except RuntimeError as exc:
        return {"error": str(exc)}

    # Sample property keys for each label (one node is enough to learn the schema)
    node_properties: dict[str, list[str]] = {}
    for label in labels:
        try:
            rows = client.run(f"MATCH (n:`{label}`) RETURN keys(n) AS props LIMIT 1")
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

    # Also get relationship property keys (sample once per type)
    try:
        rel_type_rows = client.run("CALL db.relationshipTypes()")
        rel_types = [r["relationshipType"] for r in rel_type_rows if r.get("relationshipType")]
    except Exception:
        rel_types = list({p["type"] for p in rel_patterns})

    rel_properties: dict[str, list[str]] = {}
    for rtype in rel_types:
        try:
            rows = client.run(
                f"MATCH ()-[r:`{rtype}`]->() RETURN keys(r) AS props LIMIT 1"
            )
            rel_properties[rtype] = sorted(rows[0].get("props") or []) if rows else []
        except Exception:
            rel_properties[rtype] = []

    return {
        "node_labels": labels,
        "node_properties": node_properties,
        "relationship_patterns": rel_patterns,
        "relationship_properties": rel_properties,
        "usage_hint": (
            "Use node_properties to know which property keys exist on each label. "
            "Use relationship_patterns to know valid (from)-[:TYPE]->(to) traversal paths. "
            "All identifiers are case-sensitive in Cypher."
        ),
    }
