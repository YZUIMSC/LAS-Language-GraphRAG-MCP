from __future__ import annotations

from typing import Any

from ..neo4j_client import Neo4jClient


def schema_introspection(client: Neo4jClient) -> dict[str, Any]:
    try:
        label_rows = client.run("CALL db.labels()")
        labels = [r.get("label") for r in label_rows if r.get("label")]
    except RuntimeError as exc:
        return {"error": str(exc)}

    try:
        rel_rows = client.run("CALL db.relationshipTypes()")
        relationship_types = [r.get("relationshipType") for r in rel_rows if r.get("relationshipType")]
    except RuntimeError as exc:
        return {"error": str(exc), "labels": labels}

    return {
        "labels": sorted(labels),
        "relationship_types": sorted(relationship_types),
    }
