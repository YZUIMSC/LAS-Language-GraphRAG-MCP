# Tool Selection Reference

## Decision Table

| Input Type | Primary Tool | Secondary Tool | Notes |
|---|---|---|---|
| CVE ID | `lookup_cve` | `trace_cve_to_attack` | Always call both for full context |
| CWE ID | `lookup_cwe` | — | Preserve all Related_Weakness Nature values |
| Alert text | `triage_alert` | `lookup_cwe` (if needed) | Use `include_report=True` for markdown output |
| Product / vendor keyword | `lookup_cpe_vulnerabilities` | `lookup_cve` (for top CVEs) | Keyword must be >= 3 characters |
| CVE + ATT&CK chain request | `trace_cve_to_attack` | `lookup_cve` | Evidence path, not runtime observation |
| Empty results / schema doubt | `schema_introspection` | — | No parameters needed |

---

## Per-Tool Reference

### `lookup_cve`

| Field | Value |
|---|---|
| Tool name | `lookup_cve` |
| Required parameters | `cve_id: str` |
| Optional parameters | none |
| When to call | Any input with explicit CVE ID |
| Key output fields | `found`, `description`, `cvss3`, `cvss2`, `cwes`, `cpes`, `references`, `error` |

**Correct usage:**
```
lookup_cve("CVE-2021-44228")
```

**Common misuse:**
- Calling with a partial ID like `"44228"` — must include full `CVE-YYYY-NNNNN` format
- Assuming `found=True` without checking the field
- Ignoring `error` when `found=False`

---

### `lookup_cwe`

| Field | Value |
|---|---|
| Tool name | `lookup_cwe` |
| Required parameters | `cwe_id: str` |
| Optional parameters | none |
| When to call | Input contains explicit CWE ID, or CVE trace returns CWEs for deeper analysis |
| Key output fields | `found`, `name`, `description`, `abstraction`, `related_cwes`, `capecs`, `mitigations`, `consequences`, `error` |

**Correct usage:**
```
lookup_cwe("CWE-79")
```

**Critical field: `related_cwes`**
Each entry: `{nature: str, target: str, target_name: str | None}`

All `nature` values must be preserved and surfaced:
- `ChildOf` — is a specific case of parent
- `ParentOf` — has a more specific child
- `PeerOf` — parallel weakness
- `CanPrecede` — this leads to another weakness
- `CanFollow` — results from another weakness
- `StartsWith` — initiates a chain
- `FollowedBy` — something follows this
- `Requires` / `RequiredBy` — dependency relationship
- `CanAlsoBe` — alternate manifestation

**Common misuse:**
- Dropping `related_cwes` entries that seem "less relevant"
- Only reporting `ChildOf` and ignoring `CanPrecede` or chain relationships
- Treating `capecs` list as proof of attack execution

---

### `trace_cve_to_attack`

| Field | Value |
|---|---|
| Tool name | `trace_cve_to_attack` |
| Required parameters | `cve_id: str` |
| Optional parameters | none |
| When to call | After `lookup_cve`, when CVE → ATT&CK mapping is needed |
| Key output fields | `found`, `paths`, `warnings` |

**`paths` structure:**
```json
{
  "source": "CVE-2023-5457",
  "steps": [
    {"label": "CVE", "id": "CVE-2023-5457"},
    {"relationship": "Problem_Type"},
    {"label": "CWE", "id": "CWE-1269", "name": "Product Released in Non-Release Configuration"},
    {"relationship": "RelatedAttackPattern"},
    {"label": "CAPEC", "id": "CAPEC-439", "name": "Manipulation During Distribution"},
    {"relationship": "Mapped_Attack"},
    {"label": "ATTACK", "id": "1195", "name": "T1195 - Supply Chain Compromise"}
  ],
  "confidence": "knowledge_graph_mapping",
  "limitations": [
    "This path represents a knowledge-graph mapping, not observed attacker behavior.",
    "CAPEC/ATT&CK associations are derived from NVD/MITRE data and may not reflect the specific exploitation technique used in this alert."
  ]
}
```

**Backward-compat flat fields** (still present): `cwe`, `cwe_name`, `capec`, `capec_name`, `attack`

**GraphKer relationship names used in `steps`:**
- `Problem_Type` — CVE → CWE edge
- `RelatedAttackPattern` — CWE → CAPEC edge
- `Mapped_Attack` — CAPEC → ATTACK edge (only 308 edges exist; most CAPECs have no ATT&CK mapping)

**Common misuse:**
- Interpreting `confidence: "knowledge_graph_mapping"` as "attack was observed"
- Ignoring `limitations[]` entries
- Fabricating ATT&CK IDs when `paths` is empty
- Treating `warnings` as unimportant when paths are incomplete

---

### `lookup_cpe_vulnerabilities`

| Field | Value |
|---|---|
| Tool name | `lookup_cpe_vulnerabilities` |
| Required parameters | `keyword: str` (min 3 chars) |
| Optional parameters | `limit: int` (default 100) |
| When to call | Input contains product name, vendor, or CPE keyword |
| Key output fields | `keyword`, `count`, `truncated`, `warning`, `results`, `error` |

**`results` entry structure:**
```json
{
  "cve": "CVE-XXXX-XXXX",
  "cpe": "cpe:2.3:a:apache:struts:2.5.12:...",
  "vulnerable": true,
  "score": 9.8,
  "severity": "CRITICAL",
  "cwes": ["CWE-20"]
}
```

**Mandatory `warning` field text:**
> "Results are based on substring match of CPE URI strings, not a precise CPE inventory match. Validate affected assets separately."

Always surface this. Never omit it.

**Common misuse:**
- Using a keyword shorter than 3 characters (returns error, not results)
- Treating results as confirmed asset exposure without inventory validation
- Ignoring `truncated=True` (means results are incomplete)
- Claiming specific assets are vulnerable based solely on keyword match

---

### `triage_alert`

| Field | Value |
|---|---|
| Tool name | `triage_alert` |
| Required parameters | `alert_text: str` |
| Optional parameters | `product_hint: str`, `asset_hint: str`, `include_report: bool` |
| When to call | Input is raw alert, event, or log snippet |
| Key output fields | `mode`, `input`, `extracted`, `results`, `assessment`, `evidence_paths`, `report` |

**`assessment` structure:**
```json
{
  "observed_signals": ["..."],
  "graph_context_signals": ["..."],
  "prioritization_signals": ["..."],
  "warnings": ["..."],
  "limitations": ["..."]
}
```

**Three-signal separation rule:**
- `observed_signals` → what the alert text stated
- `graph_context_signals` → what the knowledge graph infers
- `prioritization_signals` → CVSS, patch, severity data

Never merge these in the response. Each layer has different epistemic weight.

**Common misuse:**
- Not passing `include_report=True` when a full markdown report is needed
- Ignoring `assessment.warnings` and `assessment.limitations`
- Treating `evidence_paths` entries as confirmed attack behavior
- Forgetting to check `results.product_vulnerabilities` when `product_hint` was provided

---

### `schema_introspection`

| Field | Value |
|---|---|
| Tool name | `schema_introspection` |
| Required parameters | none |
| Optional parameters | none |
| When to call | Empty results, `found=False` for known entities, suspected schema mismatch |
| Key output fields | `labels`, `relationship_types`, `node_counts`, `edge_counts`, `health_warnings`, `error` |

**Healthy graph indicators:**
- `labels` includes: `CVE`, `CWE`, `CAPEC`, `ATTACK`, `CPE`
- `node_counts["CVE"]` > 0 (populated)
- `edge_counts["CAPEC_to_ATTACK"]` > 0 (ATT&CK mapping available)
- `health_warnings` is empty

**Unhealthy indicators:**
- Any `node_counts` value is `0` → that node type missing
- Any `node_counts` value is `-1` → count query failed
- `health_warnings` non-empty → specific structural issues
- `error` present → total connection failure

**Common misuse:**
- Using this as a general-purpose query tool
- Ignoring `-1` values (these indicate failures, not zero counts)
- Not checking `health_warnings` when diagnosing empty results
