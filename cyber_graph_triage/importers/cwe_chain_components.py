"""Importer for CWE chain component relationships missing from GraphKer import.

GraphKer's NVD/CWE XML import may not capture all Related_Weakness entries,
particularly FollowedBy edges inside Chain-structured CWEs.  This module
provides an idempotent, MERGE-based patcher that reads a local JSON patch file
and writes the missing edges into Neo4j without touching any existing data.

MCP tools remain read-only; this importer is a separate CLI-only operation.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..neo4j_client import Neo4jClient

# ── constants ────────────────────────────────────────────────────────────────

_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

_CYPHER_DIR = Path(__file__).parent.parent / "cypher"
_CYPHER_STRICT = (_CYPHER_DIR / "import_cwe_chain_component.cypher").read_text()
_CYPHER_PLACEHOLDER = (_CYPHER_DIR / "import_cwe_chain_component_placeholder.cypher").read_text()
_CYPHER_CHECK_NODE = (
    "MATCH (n:CWE {Name: $name}) "
    "RETURN n.Name AS name, n.Extended_Name AS extended_name LIMIT 1"
)

VALID_NATURES = frozenset({
    "ChildOf", "ParentOf", "PeerOf", "CanPrecede", "CanFollow",
    "StartsWith", "FollowedBy", "Requires", "RequiredBy", "CanAlsoBe",
})

DEFAULT_PATCH_FILE = Path(__file__).parent.parent / "data" / "cwe_chain_components_patch.json"

# ── validation ───────────────────────────────────────────────────────────────

def _validate_entry(entry: Any, idx: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(entry, dict):
        return [f"entry {idx} must be a dict, got {type(entry).__name__}"]
    for field in ("source", "nature", "target"):
        if field not in entry:
            errors.append(f"missing required field '{field}'")
    if "source" in entry and not _CWE_RE.match(str(entry["source"])):
        errors.append(
            f"source '{entry['source']}' is not a valid CWE ID (expected CWE-<digits>)"
        )
    if "target" in entry and not _CWE_RE.match(str(entry["target"])):
        errors.append(
            f"target '{entry['target']}' is not a valid CWE ID (expected CWE-<digits>)"
        )
    if "nature" in entry and entry["nature"] not in VALID_NATURES:
        errors.append(
            f"nature '{entry['nature']}' is not a recognised Related_Weakness Nature value; "
            f"valid values: {sorted(VALID_NATURES)}"
        )
    return errors


# ── public API ───────────────────────────────────────────────────────────────

def load_patch_file(path: Path | str) -> list[dict[str, Any]]:
    """Load and validate a CWE chain component patch JSON file.

    Raises ValueError on any validation error so the caller can abort early.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"Patch file must be a JSON array, got {type(raw).__name__}")
    validated: list[dict[str, Any]] = []
    all_errors: list[str] = []
    for i, entry in enumerate(raw):
        errs = _validate_entry(entry, i)
        if errs:
            all_errors.extend(f"  entry[{i}]: {e}" for e in errs)
        else:
            validated.append(entry)
    if all_errors:
        raise ValueError("Patch file validation failed:\n" + "\n".join(all_errors))
    return validated


def build_import_params(entry: dict[str, Any]) -> dict[str, Any]:
    """Convert a patch entry into Neo4j query parameters."""
    return {
        "source":      entry["source"].upper(),
        "nature":      entry["nature"],
        "target":      entry["target"].upper(),
        "target_name": entry.get("target_name", ""),
        "source_type": entry.get("source_type", "cwe_chain_component_patch"),
        "source_url":  entry.get("source_url", ""),
        "notes":       entry.get("notes", ""),
    }


def run_import(
    client: Neo4jClient,
    entries: list[dict[str, Any]],
    *,
    dry_run: bool = False,
    allow_create_placeholder: bool = False,
    input_file: str = "",
) -> dict[str, Any]:
    """Import CWE chain component relationships into Neo4j.

    Idempotent: uses MERGE so repeated runs produce no duplicates.
    MCP tools are unaffected; this function is only called from the CLI.

    Args:
        client: Neo4jClient instance.
        entries: Validated patch entries from load_patch_file().
        dry_run: Validate and report plan without writing to Neo4j.
        allow_create_placeholder: If True, create a stub CWE node when the
            target does not exist.  Default False (skip with warning).
        input_file: Original file path, included in the output for traceability.

    Returns:
        Result dict with keys: dry_run, input_file, total, imported, skipped,
        warnings, results.
    """
    results: list[dict[str, Any]] = []
    warnings: list[str] = []
    imported = 0
    skipped = 0

    for entry in entries:
        params = build_import_params(entry)
        label = f"{params['source']} -[{params['nature']}]-> {params['target']}"

        if dry_run:
            results.append({
                "source": params["source"],
                "nature": params["nature"],
                "target": params["target"],
                "status": "dry_run",
            })
            imported += 1
            continue

        # Verify source node exists
        try:
            src_rows = client.run(_CYPHER_CHECK_NODE, name=params["source"])
        except RuntimeError as exc:
            msg = f"Neo4j error checking {params['source']}: {exc}"
            warnings.append(msg)
            results.append(_skip(params, msg))
            skipped += 1
            continue

        if not src_rows:
            msg = (
                f"{params['source']} not found in Neo4j; "
                "cannot create a relationship from an unknown source CWE."
            )
            warnings.append(msg)
            results.append(_skip(params, msg))
            skipped += 1
            continue

        # Verify target node exists
        try:
            tgt_rows = client.run(_CYPHER_CHECK_NODE, name=params["target"])
        except RuntimeError as exc:
            msg = f"Neo4j error checking {params['target']}: {exc}"
            warnings.append(msg)
            results.append(_skip(params, msg))
            skipped += 1
            continue

        placeholder_created = False
        if not tgt_rows:
            if not allow_create_placeholder:
                msg = (
                    f"{params['target']} not found in Neo4j. "
                    "Use --allow-create-placeholder to create a stub node."
                )
                warnings.append(msg)
                results.append(_skip(params, msg))
                skipped += 1
                continue
            placeholder_created = True

        # Execute MERGE
        cypher = _CYPHER_PLACEHOLDER if placeholder_created else _CYPHER_STRICT
        try:
            rows = client.run(cypher, **params)
        except RuntimeError as exc:
            msg = f"Neo4j write error for {label}: {exc}"
            results.append({"source": params["source"], "nature": params["nature"],
                            "target": params["target"], "status": "error", "error": msg})
            skipped += 1
            continue

        if not rows:
            msg = f"MERGE returned no rows for {label}; relationship may not have been written."
            results.append({"source": params["source"], "nature": params["nature"],
                            "target": params["target"], "status": "error", "error": msg})
            skipped += 1
            continue

        row = rows[0]
        status = "merged_with_placeholder" if placeholder_created else "merged"
        if placeholder_created:
            warnings.append(
                f"{params['target']} did not exist — created as Placeholder node "
                f"(Extended_Name: {params['target_name'] or 'unknown'})."
            )
        results.append({
            "source": row.get("source", params["source"]),
            "nature": row.get("nature", params["nature"]),
            "target": row.get("target", params["target"]),
            "status": status,
        })
        imported += 1

    return {
        "dry_run":    dry_run,
        "input_file": input_file,
        "total":      len(entries),
        "imported":   imported,
        "skipped":    skipped,
        "warnings":   warnings,
        "results":    results,
    }


def validate_chain(
    client: Neo4jClient,
    cwe_id: str,
    patch_file: Path | str | None = None,
) -> dict[str, Any]:
    """Return a summary of chain-relevant Related_Weakness edges for a CWE.

    Cross-references against the patch file to report whether expected
    FollowedBy / StartsWith relations are present.
    """
    from ..tools.lookup_cwe import lookup_cwe  # avoid circular at module level

    cwe_id = cwe_id.upper().strip()
    result = lookup_cwe(client, cwe_id)
    if not result.get("found"):
        return {
            "cwe":    cwe_id,
            "found":  False,
            "natures": [],
            "expected_relations": [],
            "warnings": [result.get("error", f"{cwe_id} not found in Neo4j")],
        }

    related = result.get("related_cwes", [])
    natures = sorted({r["nature"] for r in related if r.get("nature")})

    # Build a set of (nature, target) pairs present in the graph
    present: set[tuple[str, str]] = {
        (r["nature"], r["target"]) for r in related if r.get("nature") and r.get("target")
    }

    # Load expected relations from patch file
    p = Path(patch_file) if patch_file else DEFAULT_PATCH_FILE
    expected_relations: list[dict[str, Any]] = []
    if p.exists():
        try:
            entries = load_patch_file(p)
            for e in entries:
                if e["source"].upper() == cwe_id:
                    tgt = e["target"].upper()
                    expected_relations.append({
                        "nature": e["nature"],
                        "target": tgt,
                        "present": (e["nature"], tgt) in present,
                    })
        except (ValueError, OSError):
            pass  # patch file issues don't block validation

    missing = [r for r in expected_relations if not r["present"]]
    chain_warnings = [
        f"Expected {r['nature']} -> {r['target']} not found in Neo4j; "
        "run import-cwe-chain-components to patch."
        for r in missing
    ]

    return {
        "cwe":               cwe_id,
        "found":             True,
        "natures":           natures,
        "expected_relations": expected_relations,
        "warnings":          chain_warnings,
    }


# ── helpers ──────────────────────────────────────────────────────────────────

def _skip(params: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "source": params["source"],
        "nature": params["nature"],
        "target": params["target"],
        "status": "skipped",
        "reason": reason,
    }
