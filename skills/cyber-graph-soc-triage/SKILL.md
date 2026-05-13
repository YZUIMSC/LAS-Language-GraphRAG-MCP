---
name: cyber-graph-soc-triage
description: Use this skill when analyzing SOC alerts, CVEs, CWEs, product/CPE hints, or vulnerability investigation tasks with the Cybersecurity Knowledge Graph MCP tools. It guides deterministic triage, evidence-path interpretation, and safe reporting without over-claiming observed attacker behavior.
---

# Cyber Graph SOC Triage Skill

## 1. When to use

Use this skill when:

- The user provides a CVE ID and wants to understand vulnerability context, CVSS scores, affected products, or ATT&CK mapping.
- The user provides a CWE ID and wants to understand weakness chains, CAPEC mappings, Related_Weakness nature relationships, mitigations, or consequences.
- The user provides alert text (SIEM alert, IDS event, log snippet) and wants an initial SOC triage result.
- The user provides a product name, vendor, or CPE keyword and wants to discover associated CVEs.
- The user wants to know whether a CVE can be mapped to ATT&CK techniques or CAPEC attack patterns.
- The user wants deterministic enrichment from the knowledge graph — not open-ended research or external threat intel.
- The user suspects a schema mismatch or empty graph and wants to debug tool output.

## 2. When not to use

Do NOT use this skill when:

- The user wants general cybersecurity education without querying the graph.
- The user wants real-time threat intelligence, active exploitation news, or current patch status — the graph database may not be current.
- The user wants arbitrary Cypher queries or free-form Text2Cypher exploration of Neo4j.
- The user wants to confirm that an attack was successful — CAPEC/ATT&CK mapping in the knowledge graph does not prove runtime exploitation.
- The user wants precise asset exposure determination without a verified CPE inventory — CPE keyword results are candidate matches only.

## 3. Available MCP tools

### `lookup_cve`

**Purpose:** Look up CVE details, CVSS scores, related CWEs, affected CPE URIs, and references.

**Parameters:**
- `cve_id` (string, required): CVE identifier, e.g., `"CVE-2021-44228"`

**Key return fields:**
- `found` (bool): Whether the CVE was found in the graph
- `description` (str | None): CVE description
- `cwes` (list[str]): Related CWE identifiers
- `cvss3` (list[dict]): CVSS v3 entries — each has `score`, `severity`, `vector`
- `cvss2` (list[dict]): CVSS v2 entries — each has `score`, `severity`, `vector`
- `cpes` (list[str]): Affected CPE URIs
- `references` (list[dict]): Each has `url`, `source`, `name`
- `error` (str, optional): Error message if connection failed

**When to call:** Any time the input contains an explicit CVE ID.

**Notes:** If `found=False` and `error` is present, report the connection failure. Do not fabricate CVE details.

---

### `lookup_cwe`

**Purpose:** Look up CWE weakness details, all Related_Weakness relationships, CAPEC mappings, mitigations, and consequences.

**Parameters:**
- `cwe_id` (string, required): CWE identifier, e.g., `"CWE-79"`

**Key return fields:**
- `found` (bool): Whether the CWE was found
- `name` (str | None): Extended CWE name
- `description` (str | None): Detailed description
- `abstraction` (str | None): Abstraction level (e.g., Base, Variant)
- `related_cwes` (list[dict]): Each entry has `nature` (str), `target` (str), `target_name` (str | None)
- `capecs` (list[dict]): Each entry has `capec` (str), `name` (str | None)
- `mitigations` (list[str])
- `consequences` (list[str])
- `error` (str, optional)

**When to call:** Any time the input contains an explicit CWE ID, or when triage extracts CWE entities.

**Critical:** Preserve ALL `related_cwes[*].nature` values. Valid nature values include: `ChildOf`, `ParentOf`, `PeerOf`, `CanPrecede`, `CanFollow`, `StartsWith`, `Requires`, `RequiredBy`, `CanAlsoBe`. (`FollowedBy` is defined in the MITRE spec but not confirmed present in the current graph import — treat it as possible but do not expect it.) Do not discard or summarize nature values — they convey structural weakness chain semantics.

---

### `trace_cve_to_attack`

**Purpose:** Trace evidence paths from CVE → CWE → CAPEC → ATT&CK. Returns structured evidence paths and warnings when ATT&CK mapping is incomplete.

**Parameters:**
- `cve_id` (string, required): CVE identifier

**Key return fields:**
- `found` (bool): Whether the CVE was found
- `paths` (list[dict]): Each path contains:
  - `source` (str): The CVE identifier
  - `steps` (list[dict]): Ordered traversal steps; each step has `label` (str), `id` (str), optionally `name` (str), and `relationship` (str) for edges
  - `confidence` (str): Always `"knowledge_graph_mapping"`
  - `limitations` (list[str]): Mandatory caveats about data interpretation
  - `cwe`, `cwe_name`, `capec`, `capec_name`, `attack` (backward-compat flat fields)
- `warnings` (list[str]): Present when ATT&CK mapping is missing or data is incomplete

**When to call:** After `lookup_cve`, when you need CVE → ATT&CK evidence path.

**Critical:** `confidence: "knowledge_graph_mapping"` means a knowledge graph path was found — it does NOT mean the attack technique was observed in practice. Always surface `limitations` in your response.

---

### `lookup_cpe_vulnerabilities`

**Purpose:** Find CVEs associated with CPE URIs that contain a given product or vendor keyword.

**Parameters:**
- `keyword` (string, required): Product or vendor keyword, minimum 3 characters. E.g., `"apache:struts"`, `"openssl"`, `"cisco:ios"`
- `limit` (int, optional, default=100): Maximum number of results

**Key return fields:**
- `keyword` (str): The keyword searched
- `count` (int): Number of returned results
- `truncated` (bool): `true` if more results exist beyond the limit
- `warning` (str): Always present — states results are substring matches, not exact inventory
- `results` (list[dict]): Each entry has `cve`, `cpe`, `vulnerable`, `score`, `severity`, `cwes`
- `error` (str, optional): Present if keyword is too short or connection failed

**When to call:** When the user provides a product name, vendor, or CPE keyword.

**Critical:** Results are substring matches against CPE URI strings. They are NOT a precise inventory match. Always surface the `warning` field. Do not claim a specific asset is vulnerable based solely on these results.

---

### `triage_alert`

**Purpose:** Perform deterministic SOC triage on alert text. Extracts CVE/CWE entities, runs graph queries, and returns a structured result with optional Markdown report.

**Parameters:**
- `alert_text` (string, required): Raw alert or event text
- `product_hint` (string | None, optional): Product name to supplement CPE lookup
- `asset_hint` (string | None, optional): Asset identifier for context
- `include_report` (bool, optional, default=False): Set `true` to get a Markdown triage report in `report` field

**Key return fields:**
- `mode` (str): Always `"SOC_TRIAGE"`
- `input` (dict): Echo of `alert_text`, `product_hint`, `asset_hint`
- `extracted` (dict): `cves`, `cwes`, `product_hint`, `asset_hint`
- `results` (dict): `cves` (lookup results), `cve_traces` (trace results), `cwes` (CWE results), `product_vulnerabilities` (CPE results)
- `assessment` (dict):
  - `observed_signals` (list[str]): Signals derived from alert text itself
  - `graph_context_signals` (list[str]): Signals from knowledge graph mapping
  - `prioritization_signals` (list[str]): CVSS scores, severity, patch/advisory signals
  - `warnings` (list[str]): Warnings from trace operations
  - `limitations` (list[str]): Data interpretation caveats
- `evidence_paths` (list[dict]): Evidence path objects from CVE traces
- `report` (str | None): Markdown report if `include_report=True`

**When to call:** When the input is an alert text rather than a direct CVE/CWE/CPE query.

---

### `schema_introspection`

**Purpose:** Return Neo4j graph labels, relationship types, node/edge counts, and health warnings. Use to debug schema compatibility or verify graph population.

**Parameters:** None

**Key return fields:**
- `labels` (list[str]): All node labels in the database
- `relationship_types` (list[str]): All relationship types
- `node_counts` (dict): Counts for `CVE`, `CWE`, `CAPEC`, `ATTACK`, `CPE`. Value `-1` if count failed.
- `edge_counts` (dict): Counts for `CVE_to_CWE`, `CWE_to_CAPEC`, `CAPEC_to_ATTACK`, `CVE_to_CPE`. Value `-1` if count failed.
- `health_warnings` (list[str]): Non-empty means graph has structural issues (e.g., missing node types, no edges)
- `error` (str, optional): Present if the labels/relationships query failed entirely

**When to call:** When tool results are unexpectedly empty, when `found=False` for known entities, or when debugging schema mismatch.

## 4. Tool selection workflow

```
IF input contains CVE ID(s):
  1. call lookup_cve(cve_id)
  2. call trace_cve_to_attack(cve_id)
  3. summarize: CVSS scores, CWEs, CPEs, references, evidence paths, limitations, warnings
  4. if CVE links to CWEs and deeper weakness analysis is needed, call lookup_cwe(cwe_id)

IF input contains CWE ID(s) only:
  1. call lookup_cwe(cwe_id)
  2. preserve ALL related_cwes[*].nature values in response
  3. highlight chain/composite relations: ChildOf, ParentOf, CanPrecede, CanFollow, StartsWith

IF input is alert text:
  1. call triage_alert(alert_text, product_hint, asset_hint, include_report=True)
  2. inspect extracted.cves — for each CVE, check results.cves[cve_id] and results.cve_traces[cve_id]
  3. inspect extracted.cwes — for each CWE, check results.cwes[cwe_id]
  4. if product_hint is present, check results.product_vulnerabilities
  5. surface assessment.observed_signals, graph_context_signals, prioritization_signals separately
  6. surface assessment.warnings and assessment.limitations

IF input contains product/vendor/CPE keyword:
  1. validate keyword length >= 3 characters before calling
  2. call lookup_cpe_vulnerabilities(keyword, limit)
  3. treat results as candidate matches — surface the warning field
  4. do NOT claim a specific asset is confirmed vulnerable

IF tool output is empty, found=False, or schema mismatch suspected:
  1. call schema_introspection()
  2. check labels, relationship_types, node_counts, edge_counts
  3. report health_warnings if non-empty
  4. if node_counts[x] == 0 or -1, explain what graph data is missing
```

## 5. Analysis workflow

Follow this sequence for every triage task:

1. **Extract explicit entities** from user input: CVE IDs, CWE IDs, product/vendor keywords, alert text.
2. **Query only relevant tools** — do not call all six tools for every input.
3. **Read all output fields** including `found`, `error`, `warnings`, `limitations`, `truncated`, `warning` (CPE). Do not skip any.
4. **Separate observation layers:**
   - What the alert text itself contains (observed_signals)
   - What the knowledge graph infers (graph_context_signals)
   - What CVSS/patch data indicates (prioritization_signals)
5. **Use evidence paths** (`steps`, `confidence`, `limitations`) to support any graph-derived statements.
6. **Produce triage report** with findings, limitations, and recommended next actions.
7. **Do not request arbitrary Cypher** — use only the six provided MCP tools.

## 6. Evidence path interpretation

Evidence paths from `trace_cve_to_attack` represent knowledge graph traversals, not observed runtime behavior.

**Interpreting `paths[*]`:**
- `steps`: An ordered list of nodes and relationships traversed. Each node step has `label`, `id`, and optionally `name`. Each edge step has `relationship`. Read the path as: CVE -[Problem_Type]-> CWE -[RelatedAttackPattern]-> CAPEC -[Mapped_Attack]-> ATT&CK. These are the GraphKer relationship names used in this graph.
- `confidence: "knowledge_graph_mapping"`: The path was derived from knowledge graph data. It does NOT mean the technique was observed in the alert or that exploitation succeeded.
- `limitations`: Mandatory caveats that MUST be included in any response. Common examples: "CVE→ATT&CK mapping is knowledge graph derived, not observed telemetry", "CAPEC patterns describe attack classes, not specific exploits".

**Rules:**
- If a path ends at CAPEC with no ATT&CK node, only claim CVE → CWE → CAPEC mapping. Do not infer or add ATT&CK technique IDs.
- If `paths` is empty and `warnings` is non-empty, report the missing mapping and the warnings verbatim.
- If `found=False`, do not synthesize a path from external knowledge.
- Always summarize or quote key `steps` in your response — do not omit the path structure.

## 7. Risk signal interpretation

`triage_alert` and `trace_cve_to_attack` produce three signal layers. Always present them separately:

**`observed_signals`**
Signals derived directly from the alert text. These represent what the input itself stated or contained. Example: "CVE-2021-44228 extracted from alert text", "Product hint: log4j".

**`graph_context_signals`**
Signals derived from knowledge graph relationships. These represent graph-level associations, not observed events. Example: "CVE-2021-44228 maps to CWE-917 → CAPEC-137 → ATT&CK T1190". Use cautious language: "knowledge graph associates", "graph mapping suggests", "candidate technique".

**`prioritization_signals`**
Signals for triage priority decisions. Example: "CVSS 10.0 Critical", "patch advisory available in references", "multiple CPE products affected". These inform urgency — they do not prove active exploitation.

**Never mix these layers.** Do not present a graph_context_signal as if it were an observed_signal. Do not treat prioritization_signals as confirmation of compromise.

## 8. Safety and overclaiming rules

These rules are mandatory. Violating them produces misleading SOC triage output.

1. **Do not claim exploitation succeeded** unless the alert explicitly includes evidence of success (e.g., "exploitation confirmed", "shell established", "data exfiltrated").
2. **Do not claim an ATT&CK technique was observed** solely because a CVE maps to CAPEC which maps to ATT&CK in the knowledge graph.
3. **Do not claim an asset is vulnerable** solely because a CPE keyword query returned a match. CPE results are substring matches, not verified inventory.
4. **Do not treat CVSS High/Critical as proof of active exploitation.** CVSS measures severity if exploited, not likelihood or confirmation of exploitation.
5. **Do not ignore warnings, limitations, errors, or truncated flags.** If `truncated=True`, note that results were capped. If `limitations` is non-empty, include them. If `error` is present, report it.
6. **Do not request or execute arbitrary Cypher** in triage mode. Use only the six MCP tools.
7. **Do not recommend destructive actions.** All remediation recommendations should be verification-oriented (patch, isolate, validate, confirm) — not commands to delete, block, or kill without human review.
8. **Do not fabricate CVE, CWE, or ATT&CK data** if `found=False`. Report what the graph returned.

## 9. Response format

Structure every triage response as follows:

```
## Summary
One to three sentences. What was analyzed, what the graph returned, overall confidence level.

## Observed Evidence
Entities and signals extracted directly from the input/alert text.
- extracted_cves: [...]
- extracted_cwes: [...]
- product_hint: ...
- observed_signals: [...]

## Knowledge Graph Context
Graph-derived associations. Use cautious language.
- CVE details: description, CVSS, CWEs, CPEs
- CVE → CWE → CAPEC → ATT&CK mapping (if found)
- CWE weakness chains (Related_Weakness Nature values)
- graph_context_signals: [...]

## Evidence Paths
Structured paths from trace_cve_to_attack. Quote key steps. Note confidence level.
Example: CVE-2021-44228 -[HAS_WEAKNESS]-> CWE-917 -[MAPS_TO]-> CAPEC-137 -[RELATED_TO]-> T1190
confidence: knowledge_graph_mapping

## Risk Signals
- Prioritization: CVSS scores, severity, patch/advisory availability
- prioritization_signals: [...]

## Limitations
Copy all limitations[] and warnings[] fields from tool output verbatim.

## Recommended Next Actions
Verification-oriented actions only. E.g.:
- Validate patch status for CVE-XXXX-XXXX
- Confirm whether affected CPE products exist in asset inventory
- Escalate if asset_hint matches known critical asset
```

**Language guidance:**
- Use "knowledge graph associates", "graph mapping indicates", "candidate technique", "possible attack pattern" for graph_context_signals.
- Use "alert states", "extracted from input" for observed_signals.
- If data is insufficient, write explicitly: "No CVE found in graph for this ID." Do not fill gaps with assumptions.

## 10. Examples

See `examples/` directory for complete worked examples:

- [`alert_with_cve.md`](examples/alert_with_cve.md) — Alert text containing a CVE ID
- [`alert_with_cwe_chain.md`](examples/alert_with_cwe_chain.md) — Alert with CWE and weakness chain analysis
- [`product_cpe_lookup.md`](examples/product_cpe_lookup.md) — Product/vendor keyword CPE vulnerability lookup
- [`schema_debug.md`](examples/schema_debug.md) — Debugging empty results with schema_introspection

## 11. Failure handling

| Failure condition | Action |
|---|---|
| `found=False`, no `error` | Report: "Entity not found in knowledge graph." Do not fabricate data. |
| `found=False`, `error` present | Report the error message. Suggest checking Neo4j connectivity. |
| `truncated=True` | Note results are capped at limit. Suggest refining keyword or increasing limit. |
| `health_warnings` non-empty | Quote warnings. Explain which graph data is missing. |
| `error` in CPE lookup (keyword too short) | Ask user for a keyword of at least 3 characters. |
| `paths` empty in trace_cve_to_attack | Report: "No CVE → ATT&CK path found in graph." Quote `warnings` field. |
| `limitations` non-empty | Always include limitations verbatim in the response. |
| All node_counts are 0 or -1 | Report graph is unpopulated. Advise running the data import pipeline. |
| Neo4j connection error | Report connection failure. Do not retry automatically. Ask user to verify environment. |
