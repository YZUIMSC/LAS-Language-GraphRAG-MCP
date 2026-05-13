# Example: Schema Debug With schema_introspection

## User Input

```
I ran triage_alert on an alert containing CVE-2023-44487, but the result shows
found=False and evidence_paths is empty. The same CVE is definitely in NVD.
Can you check if the graph is populated correctly?
```

## Tool Sequence

1. Call `schema_introspection()` — no parameters required
2. Read all return fields: `labels`, `relationship_types`, `node_counts`, `edge_counts`, `health_warnings`, `error`
3. Diagnose based on counts and warnings
4. If graph appears healthy but CVE is missing, note that graph coverage depends on import scope

## Expected Reasoning

**Step 1: Call schema_introspection()**

This tool requires no parameters and queries the Neo4j database metadata directly.

**Step 2: Read labels and relationship_types**

Expected labels for a healthy GraphKer-populated graph:
`["ATTACK", "CAPEC", "CPE", "CVE", "CWE"]` (plus any others)

Expected relationship types (GraphKer canonical names):
`["Problem_Type", "RelatedAttackPattern", "Mapped_Attack", "applicableIn", "Related_Weakness", "CVSS3_Impact", "CVSS2_Impact", "referencedBy", "hasMitigation", "hasConsequence"]`

If labels are empty or missing expected types → the graph import may have failed or used a different schema.

**Step 3: Read node_counts**

```
node_counts: {
  "CVE": 319626,    # populated
  "CWE": 1384,      # populated
  "CAPEC": 693,     # populated
  "ATTACK": 222,    # populated
  "CPE": 1502334    # populated
}
```

If any count is `0`: that node type was not imported.
If any count is `-1`: the count query failed (connectivity or permission issue).

A count of `0` for CVE means NO CVEs are in the graph — any `lookup_cve` or `triage_alert` with CVEs will return `found=False`. This explains the user's issue.

**Step 4: Read edge_counts**

```
edge_counts: {
  "CVE_to_CWE": 319626,     # populated (Problem_Type edges)
  "CWE_to_CAPEC": 8000,     # populated (RelatedAttackPattern edges)
  "CAPEC_to_ATTACK": 308,   # populated — only 308 CAPEC→ATT&CK mappings exist in this import
  "CVE_to_CPE": 900000      # populated (applicableIn edges)
}
```

If `CAPEC_to_ATTACK: 0` → `trace_cve_to_attack` will never return ATT&CK nodes. (Healthy graph has 308 Mapped_Attack edges — most CAPECs have no ATT&CK mapping.)
If `CVE_to_CWE: 0` → CVEs cannot be linked to CWEs; evidence paths will be empty.

**Step 5: Read health_warnings**

`health_warnings` is a list of strings. Each warning indicates a specific structural issue:
- `"No CVE nodes found"` → graph unpopulated
- `"No CAPEC→ATTACK edges"` → ATT&CK mapping layer missing
- `"No CVE→CWE edges"` → CVE-to-weakness links missing

Empty `health_warnings` (`[]`) means the graph passed basic structural checks.

**Step 6: Diagnose the user's issue**

Scenario A: `node_counts["CVE"] = 0` and health_warnings includes "No CVE nodes found"
→ Graph has no CVE data. The CVE-2023-44487 not found is expected. Data import needed.

Scenario B: `node_counts["CVE"] = 319626` but CVE-2023-44487 specifically is missing
→ Graph is populated, but this specific CVE was not included in the import dataset.
→ The NVD entry exists but was not part of the imported data snapshot.

Scenario C: `error` field present in schema_introspection result
→ Neo4j connection failure. The graph is unreachable — explains all `found=False` results.

Scenario D: `labels` list is empty or does not contain "CVE"
→ Schema mismatch — the graph was not populated with the expected GraphKer schema.

**What NOT to say:**
- Do not claim the CVE data is wrong
- Do not attempt to manually create graph nodes
- Do not recommend arbitrary Cypher queries

## Expected Response Skeleton

```
## Summary
schema_introspection run to diagnose why CVE-2023-44487 returned found=False.
[Based on results, one of the following:]

SCENARIO A (graph unpopulated):
Graph has 0 CVE nodes — data import has not been run or failed.
CVE-2023-44487 not found is expected behavior.

SCENARIO B (graph healthy, CVE missing):
Graph is healthy with [N] CVE nodes (expected ~319626), but CVE-2023-44487 is not in the imported dataset.

SCENARIO C (connection error):
Neo4j connection failed — all tool queries will return found=False until fixed.

## Schema Inspection Results

Labels found: [list from labels field]
Relationship types found: [list from relationship_types field]

Node counts:
- CVE: [count]
- CWE: [count]
- CAPEC: [count]
- ATTACK: [count]
- CPE: [count]

Edge counts:
- CVE_to_CWE: [count]
- CWE_to_CAPEC: [count]
- CAPEC_to_ATTACK: [count]
- CVE_to_CPE: [count]

Health warnings: [list verbatim, or "none" if empty]

## Diagnosis

[SCENARIO A]
Node count for CVE is 0. health_warnings includes "No CVE nodes found".
The graph database has not been populated with CVE data.
All lookup_cve and triage_alert calls will return found=False.

[SCENARIO B]
Graph structure is healthy. CVE count is non-zero.
CVE-2023-44487 was not included in the data import snapshot.
This is a coverage gap, not a connectivity or schema issue.

[SCENARIO C]
schema_introspection returned error: "[error message]"
Neo4j is unreachable. Verify NEO4J_URI, credentials, and database availability.

## Limitations
- schema_introspection confirms schema structure but cannot determine import date or NVD coverage.
- A healthy schema does not guarantee all CVEs are present.

## Recommended Next Actions
[SCENARIO A]
- Run the GraphKer or data import pipeline to populate the graph
- Re-run schema_introspection after import to verify node counts

[SCENARIO B]
- Check the data import scope — CVE-2023-44487 may be in a newer NVD dataset
- Re-run the import with updated NVD data if the CVE is recent
- For now, retrieve CVE-2023-44487 details from NVD directly

[SCENARIO C]
- Verify Neo4j is running: check NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD in .env
- Test connectivity with: cypher-shell -a <uri> -u <user> -p <pass>
- Re-run triage after connectivity is restored
```
