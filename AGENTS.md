# AGENTS.md — Cyber Graph Triage MCP Server

This file is written for LLM agents. Read it before calling any tool.
It tells you what this server does, what tools are available, how to use
them correctly, and what the underlying data looks like.

---

## What This Server Does

This MCP server gives you **read-only, deterministic access** to a Neo4j
cybersecurity knowledge graph built with GraphKer. It is designed for
**SOC triage (Mode A)**: given an alert or a CVE/CWE ID, you can retrieve
structured vulnerability context, weakness chains, attack pattern mappings,
and affected product inventories.

You cannot write to the graph. You cannot run free-form Cypher. Every tool
executes a fixed, vetted query.

---

## Graph Scale (live counts)

| Node type | Count     |
|-----------|-----------|
| CVE       | 319,626   |
| CPE       | 1,502,334 |
| CWE       | 1,384     |
| CAPEC     | 693       |
| ATTACK    | 222       |

| Edge                        | Count     |
|-----------------------------|-----------|
| CVE → CWE (Problem_Type)    | 334,891   |
| CVE → CPE (applicableIn)    | 2,795,461 |
| CWE → CAPEC (RelatedAttackPattern) | 1,212 |
| CAPEC → ATTACK (Mapped_Attack) | 308   |

The CAPEC→ATTACK coverage is intentionally sparse: only 308 edges exist
across 693 CAPEC nodes. Do not assume every CVE has an ATT&CK mapping.

---

## Tools Reference

### `lookup_cve(cve_id)`

Look up a single CVE.

**Input:** `cve_id` — string, e.g. `"CVE-2023-5457"`. Case-insensitive.

**Returns:**

```json
{
  "found": true,
  "cve": "CVE-2023-5457",
  "description": "...",
  "published_date": "2023-10-10T...",
  "last_modified_date": "...",
  "cwes": ["CWE-1269"],
  "cvss3": [{"score": 7.8, "severity": "HIGH", "vector": "CVSS:3.1/..."}],
  "cvss2": [{"score": 6.9, "severity": null, "vector": "AV:L/..."}],
  "cpes": ["cpe:2.3:...", "..."],
  "references": [{"url": "https://...", "source": "...", "name": "..."}]
}
```

If the CVE is not in the graph: `{"found": false, "cve": "CVE-..."}`.
If the database is unreachable: `{"found": false, "error": "Cannot connect..."}`.

**Notes:**
- `cpes` is capped at 20 entries.
- `references` is capped at 20 entries.
- `cvss3` may be an empty list if no CVSS3 score exists.
- `description` is always a plain string (not a list).

---

### `lookup_cwe(cwe_id)`

Look up a single CWE with its full weakness chain context.

**Input:** `cwe_id` — string, e.g. `"CWE-692"`. Case-insensitive.

**Returns:**

```json
{
  "found": true,
  "cwe": "CWE-692",
  "name": "Incomplete Denylist to Cross-Site Scripting",
  "description": "...",
  "abstraction": "Compound",
  "structure": "Chain",
  "status": "Draft",
  "related_cwes": [
    {"nature": "StartsWith", "target": "CWE-184", "target_name": "..."},
    {"nature": "ChildOf",    "target": "CWE-184", "target_name": "..."}
  ],
  "capecs": [
    {"capec": "CAPEC-80", "name": "Using UTF-8 Encoding to Bypass Validation Logic"}
  ],
  "mitigations": ["..."],
  "consequences": ["Confidentiality", "Integrity", "Availability"]
}
```

**Critical:** `related_cwes` is **never filtered by Nature**. All values are
returned as-is from the graph, including:

| Nature | Meaning |
|--------|---------|
| `ChildOf` | This CWE is a specialisation of another |
| `ParentOf` | This CWE generalises another |
| `PeerOf` | Related at the same abstraction level |
| `CanPrecede` | This CWE can lead to the target CWE |
| `CanFollow` | This CWE can result from the target CWE |
| `StartsWith` | First step in a Chain CWE |
| `Requires` / `RequiredBy` | Dependency relationships |
| `CanAlsoBe` | Situation-dependent classification |

For Chain CWEs (e.g. CWE-692), look for `StartsWith` to identify the
initiating weakness in the chain.

---

### `trace_cve_to_attack(cve_id)`

Trace the evidence path CVE → CWE → CAPEC → ATT&CK.

**Input:** `cve_id` — string.

**Returns:**

```json
{
  "found": true,
  "cve": "CVE-2023-5457",
  "paths": [
    {
      "source": "CVE-2023-5457",
      "steps": [
        {"label": "CVE",   "id": "CVE-2023-5457"},
        {"relationship": "Problem_Type"},
        {"label": "CWE",   "id": "CWE-1269", "name": "Product Released in Non-Release Configuration"},
        {"relationship": "RelatedAttackPattern"},
        {"label": "CAPEC", "id": "CAPEC-439", "name": "Manipulation During Distribution"},
        {"relationship": "Mapped_Attack"},
        {"label": "ATTACK","id": "1195", "name": "T1195 - Supply Chain Compromise"}
      ],
      "confidence": "knowledge_graph_mapping",
      "limitations": [
        "This path represents a knowledge-graph mapping, not observed attacker behavior.",
        "CAPEC/ATT&CK associations are derived from NVD/MITRE data and may not reflect the specific exploitation technique used in this alert."
      ],
      "cwe": "CWE-1269",
      "cwe_name": "...",
      "capec": "CAPEC-439",
      "capec_name": "...",
      "attack": {"id": "1195", "name": "T1195 - Supply Chain Compromise", "relation": "Mapped_Attack"}
    }
  ],
  "warnings": []
}
```

**When ATT&CK mapping is absent:**
- `attack` is `null` in the path entry.
- `warnings` contains: `"No ATT&CK mapping found from CAPEC nodes..."`.
- This is normal — only 308 of 693 CAPEC nodes have ATT&CK edges.

**Do not** tell users an attack technique was observed just because a path
exists. The `confidence` field and `limitations` must be surfaced.

---

### `lookup_cpe_vulnerabilities(keyword, limit=100)`

Find CVEs whose affected CPE URIs contain a substring.

**Input:**
- `keyword` — string, minimum 3 characters. Examples: `"cisco:ios_xr"`,
  `"apache:struts"`, `"openssl"`.
- `limit` — integer, default 100, max your discretion.

**Returns:**

```json
{
  "keyword": "apache:struts",
  "count": 87,
  "truncated": false,
  "warning": "Results are based on substring match of CPE URI strings, not a precise CPE inventory match. Validate affected assets separately.",
  "results": [
    {
      "cve": "CVE-2017-5638",
      "cpe": "cpe:2.3:a:apache:struts:2.3.5:*:*:*:*:*:*:*",
      "vulnerable": true,
      "score": 10.0,
      "severity": "CRITICAL",
      "cwes": ["CWE-20"]
    }
  ]
}
```

**If keyword is too short:** returns an error with guidance, no query runs.

**If `truncated` is `true`:** there are more results in the database than
were returned. Use a more specific keyword or increase `limit`.

**Important:** CPE URI substring match is not the same as confirming an
asset is affected. Always remind users to validate against their inventory.

---

### `triage_alert(alert_text, product_hint=null, asset_hint=null, include_report=false)`

Full SOC triage pipeline from free-form alert text.

**Input:**
- `alert_text` — the raw alert or incident description.
- `product_hint` — optional product keyword for CPE lookup (e.g. `"cisco:ios_xr"`).
- `asset_hint` — optional asset identifier for context (stored but not queried).
- `include_report` — if `true`, adds a Markdown report string to the response.

**What it does internally:**
1. Extracts CVE/CWE IDs from `alert_text` using regex.
2. Calls `lookup_cve` + `trace_cve_to_attack` for each CVE.
3. Calls `lookup_cwe` for each CWE.
4. Calls `lookup_cpe_vulnerabilities` if `product_hint` is given.
5. Assembles a three-layer assessment.

**Returns:**

```json
{
  "mode": "SOC_TRIAGE",
  "input": {"alert_text": "...", "product_hint": null, "asset_hint": null},
  "extracted": {"cves": ["CVE-..."], "cwes": [], "product_hint": null, "asset_hint": null},
  "results": {
    "cves": {"CVE-...": {...}},
    "cve_traces": {"CVE-...": {...}},
    "cwes": {},
    "product_vulnerabilities": []
  },
  "assessment": {
    "observed_signals":       ["Alert text contains CVE reference(s): CVE-..."],
    "graph_context_signals":  ["CVE-... → CAPEC mapping(s): CAPEC-..."],
    "prioritization_signals": ["CVE-...: CVSS3 HIGH (7.8)", "CVE-...: patch/advisory reference available"]
  },
  "evidence_paths": [...],
  "report": "# SOC Triage Report...(if include_report=true)"
}
```

**Assessment layer meanings:**

| Layer | Source | Use for |
|-------|--------|---------|
| `observed_signals` | The alert text itself | Confirming what the analyst saw |
| `graph_context_signals` | Graph traversal (KG mapping) | Attack pattern context, NOT confirmed TTPs |
| `prioritization_signals` | CVSS scores, patch refs | Deciding urgency |

---

### `schema_introspection()`

Debug tool. Returns graph labels, relationship types, node/edge counts,
and health warnings.

**Input:** none.

**Returns:**

```json
{
  "labels": ["ATTACK", "CAPEC", "CPE", "CVE", "CWE", ...],
  "relationship_types": ["Mapped_Attack", "Problem_Type", "RelatedAttackPattern", ...],
  "node_counts":  {"CVE": 319626, "CWE": 1384, "CAPEC": 693, "ATTACK": 222, "CPE": 1502334},
  "edge_counts":  {"CVE_to_CWE": 334891, "CWE_to_CAPEC": 1212, "CAPEC_to_ATTACK": 308, "CVE_to_CPE": 2795461},
  "health_warnings": []
}
```

Call this first if tool results look empty or unexpected. `health_warnings`
will flag missing node types or edge sets.

---

## Decision Guide: Which Tool to Call

```
Do you have a specific CVE ID?
  └─ YES → lookup_cve(cve_id)
           + trace_cve_to_attack(cve_id)   ← always pair these

Do you have a CWE ID (or got one from lookup_cve)?
  └─ YES → lookup_cwe(cwe_id)

Do you have a product name or vendor?
  └─ YES → lookup_cpe_vulnerabilities(keyword)
           (use "vendor:product" format when possible)

Do you have free-form alert text with CVE/CWE mentions?
  └─ YES → triage_alert(alert_text, include_report=true)
           (this orchestrates all of the above automatically)

Results look wrong or empty?
  └─ → schema_introspection()   ← check graph health first
```

---

## What These Tools Cannot Do

| Limitation | Reason |
|------------|--------|
| No free-form Cypher | Security: arbitrary queries are not permitted |
| No semantic search | Mode A only — requires explicit CVE/CWE IDs |
| No asset confirmation | No Asset nodes in this graph; CPE lookup is approximate |
| No KEV / exploit status | Not in the current graph import |
| No real-time data | Graph is a point-in-time import; check published_date |
| CAPEC→ATTACK is sparse | Only 308 edges; most CVEs will not have ATT&CK paths |

If the alert has no CVE or CWE ID, `triage_alert` will extract nothing and
`limitations` will suggest semantic search (Mode B, not yet implemented).

---

## Interpreting Evidence Paths

An evidence path like:

```
CVE-2023-5457 → [Problem_Type] → CWE-1269
             → [RelatedAttackPattern] → CAPEC-439
             → [Mapped_Attack] → T1195 Supply Chain Compromise
```

means:

- The CVE's weakness type (CWE-1269) is associated with attack pattern CAPEC-439
  in the MITRE knowledge base.
- CAPEC-439 is mapped to ATT&CK technique T1195 in the MITRE ATT&CK dataset.
- **This is a knowledge-graph inference, not an observation.**
- You must not assert that T1195 was the technique used in this specific incident.
- Surface the `limitations` array to the analyst alongside the path.

---

## Graph Schema Quick Reference

```
(CVE)-[:Problem_Type]---------->(CWE)
(CVE)-[:applicableIn]---------->(CPE)
(CVE)-[:CVSS3_Impact]---------->(CVSS_3)
(CVE)-[:CVSS2_Impact]---------->(CVSS_2)
(CVE)-[:referencedBy]---------->(Reference_Data)
(CWE)-[:Related_Weakness]----->(CWE)   # Nature property: ChildOf, StartsWith, etc.
(CWE)-[:RelatedAttackPattern]->(CAPEC)
(CWE)-[:hasMitigation]-------->(Mitigation)
(CWE)-[:hasConsequence]------->(Consequence)
(CAPEC)-[:Mapped_Attack]------>(ATTACK) # sparse — 308 edges only
```

Key property names (GraphKer schema):
- CVE: `Name`, `Description`, `Published_Date`, `Last_Modified_Date`
- CWE: `Name`, `Extended_Name`, `Description`, `Abstraction`, `Structure`, `Status`
- CAPEC: `Name`, `ExtendedName` or `Extended_Name`
- ATTACK: `ID`, `Name`, `Taxonomy`
- CPE: `uri`
- CVSS_3: `Base_Score`, `Base_Severity`, `Vector_String`
- CVSS_2: `Base_Score`, `Severity`, `Vector_String`
- Related_Weakness relationship: `Nature` property

---

## Constraints You Must Respect

1. **Never claim an attack was successful** based solely on graph mappings.
2. **Never present CAPEC/ATT&CK paths as observed TTPs** — they are KG inferences.
3. **Always surface `limitations`** from evidence paths when reporting to analysts.
4. **Do not run arbitrary Cypher** — the tools enforce read-only fixed queries.
5. **CPE results are approximate** — substring match, not confirmed asset inventory.
6. **ATT&CK absence is not meaningful** — sparse coverage means missing path ≠ no risk.
