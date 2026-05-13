# CWE Chain Component Import

## Problem

GraphKer's NVD/CWE XML import pipeline does not consistently capture all
`Related_Weakness` entries for Chain-structured CWEs. Specifically,
`FollowedBy` edges in the "Chain Components" section of CWE pages may be
absent from the Neo4j graph after a standard GraphKer import.

**Confirmed gap (as of current import):**

| CWE | Expected relation | Status |
|-----|-------------------|--------|
| CWE-692 | FollowedBy → CWE-79 | **missing** from Neo4j |
| CWE-692 | StartsWith → CWE-184 | present |
| CWE-692 | ChildOf → CWE-184 | present |

This means `lookup_cwe("CWE-692")` returns only `StartsWith` and `ChildOf`,
omitting the `FollowedBy CWE-79` edge that is visible on the official CWE
page's "Chain Components" table.

**Impact:** LLM-assisted triage using the skill file may mention that
`FollowedBy CWE-79` is absent in the graph, requiring analysts to infer the
XSS risk from the CWE name and CAPEC mappings instead of a direct graph edge.

---

## Solution: Local JSON Patch File + Idempotent Importer

Rather than rerunning or modifying the full GraphKer import, a lightweight
**patch importer** adds only the missing edges using `MERGE`, leaving all
existing graph data untouched.

### Data file

```
cyber_graph_triage/data/cwe_chain_components_patch.json
```

Format (array of patch entries):

```json
[
  {
    "source":      "CWE-692",
    "nature":      "FollowedBy",
    "target":      "CWE-79",
    "target_name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    "source_type": "cwe_official_html",
    "source_url":  "https://cwe.mitre.org/data/definitions/692.html",
    "notes":       "CWE-692 Chain Components table shows FollowedBy CWE-79."
  }
]
```

Add further entries to this file for other chain CWEs that need patching.

### Cypher used

The importer writes `Related_Weakness` edges, the same relationship type used
by GraphKer, so `lookup_cwe` picks them up with no code changes:

```cypher
MATCH (source:CWE {Name: $source})
MATCH (target:CWE {Name: $target})
MERGE (source)-[r:Related_Weakness {Nature: $nature}]->(target)
SET r.Source     = $source_type,
    r.Source_URL = $source_url,
    r.Notes      = $notes,
    r.Imported_By = "cyber_graph_triage",
    r.Imported_At = datetime()
```

`MERGE` on `{Nature: $nature}` is idempotent: re-running never creates
duplicate edges.

---

## Step-by-Step Operations

### 1. Check current state

```bash
uv run python -m cyber_graph_triage.cli validate-cwe-chain CWE-692
```

Before patching, `expected_relations[0].present` will be `false` for
`FollowedBy → CWE-79`. Exit code 2 indicates missing expected relations.

### 2. Dry-run (validate without writing)

```bash
uv run python -m cyber_graph_triage.cli import-cwe-chain-components \
  --file cyber_graph_triage/data/cwe_chain_components_patch.json \
  --dry-run
```

Output shows all relationships that _would_ be imported, without touching Neo4j.

### 3. Import

```bash
uv run python -m cyber_graph_triage.cli import-cwe-chain-components \
  --file cyber_graph_triage/data/cwe_chain_components_patch.json
```

Expected output:

```json
{
  "dry_run": false,
  "input_file": "cyber_graph_triage/data/cwe_chain_components_patch.json",
  "total": 1,
  "imported": 1,
  "skipped": 0,
  "warnings": [],
  "results": [
    {
      "source": "CWE-692",
      "nature": "FollowedBy",
      "target": "CWE-79",
      "status": "merged"
    }
  ]
}
```

### 4. Verify

```bash
uv run python -m cyber_graph_triage.cli validate-cwe-chain CWE-692
```

After patching, all three expected natures should be present:

```json
{
  "cwe": "CWE-692",
  "found": true,
  "natures": ["ChildOf", "FollowedBy", "StartsWith"],
  "expected_relations": [
    {"nature": "FollowedBy", "target": "CWE-79", "present": true}
  ],
  "warnings": []
}
```

Exit code 0 = all expected relations present.

### 5. Confirm via lookup-cwe

```bash
uv run python -m cyber_graph_triage.cli lookup-cwe CWE-692
```

`related_cwes` should now include:

```json
[
  {"nature": "StartsWith", "target": "CWE-184", "target_name": "Incomplete List of Disallowed Inputs"},
  {"nature": "ChildOf",    "target": "CWE-184", "target_name": "Incomplete List of Disallowed Inputs"},
  {"nature": "FollowedBy", "target": "CWE-79",  "target_name": "Improper Neutralization of Input..."}
]
```

---

## CLI Reference

### `import-cwe-chain-components`

| Flag | Default | Description |
|------|---------|-------------|
| `--file PATH` | required | JSON patch file path |
| `--dry-run` | false | Validate and show plan; no Neo4j writes |
| `--allow-create-placeholder` | false | Create stub CWE node if target is missing |

Exit codes: `0` = all imported, `2` = one or more skipped.

### `validate-cwe-chain <CWE-ID>`

| Flag | Default | Description |
|------|---------|-------------|
| `--patch-file PATH` | built-in patch file | Patch file to compare against |

Exit codes: `0` = all expected relations present, `2` = missing relations detected.

---

## Security Notes

- This importer is a **data maintenance tool**, not an MCP tool.
- The MCP server exposes only **read-only** tools; no write path is accessible to MCP clients.
- All patched relationships carry `Source_URL` and `Notes` metadata for auditability.
- The importer never deletes or modifies existing relationships.
- `--allow-create-placeholder` should be used with care; prefer patching only when
  the target CWE is confirmed to exist in the graph (it will for all standard CWEs).

---

## Future Work

### Strategy B: HTML/XML Parser (not yet implemented)

A more general approach would parse the CWE official HTML or XML directly:

```bash
# Planned (not yet available):
python -m cyber_graph_triage.cli parse-cwe-html \
  --file ./fixtures/cwe-692.html \
  --source CWE-692

python -m cyber_graph_triage.cli import-cwe-chain-components \
  --file generated_chain_components.json
```

**HTML target:** Parse the "Chain Components" table from CWE pages to extract
`StartsWith` and `FollowedBy` entries automatically.

**XML target:** Parse the MITRE CWE XML bundle (if available locally, since
the official download may return 403) for `Related_Weakness` elements with
`View_ID=1000` or `View_ID=699`.

For now, use the manual JSON patch file approach (Strategy A) above.
