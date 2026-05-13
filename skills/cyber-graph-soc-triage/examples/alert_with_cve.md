# Example: Alert With CVE

## User Input

```
IDS Alert [HIGH]: Inbound HTTP POST to /api/lookup with payload pattern matching
CVE-2021-44228 Log4Shell exploit signature. Source IP 203.0.113.42.
Target: prod-app-01 (10.0.1.50). Sensor: edge-ids-01. Time: 2024-01-15T08:32:11Z
```

## Tool Sequence

1. Call `triage_alert` with `alert_text`, `asset_hint="prod-app-01"`, `include_report=True`
2. Inspect `extracted.cves` → `["CVE-2021-44228"]`
3. The triage service internally calls `lookup_cve("CVE-2021-44228")` and `trace_cve_to_attack("CVE-2021-44228")`
4. If you need deeper CWE context for any CWE in `extracted.cwes`, call `lookup_cwe(cwe_id)`

Alternatively, if calling tools individually:
1. `lookup_cve("CVE-2021-44228")` — get CVSS, CWE, CPE, references
2. `trace_cve_to_attack("CVE-2021-44228")` — get CVE → CWE → CAPEC → ATT&CK evidence path

## Expected Reasoning

**Step 1: Read extracted entities**

From `triage_alert` result:
- `extracted.cves`: `["CVE-2021-44228"]`
- `extracted.cwes`: may include CWEs linked from CVE lookup
- `input.asset_hint`: `"prod-app-01"`

**Step 2: Interpret lookup_cve result**

Check `results.cves["CVE-2021-44228"]`:
- `found=True` (if CVE is in graph)
- `cvss3[0].score` — likely 10.0, `severity` "CRITICAL"
- `cwes` — e.g., `["CWE-917"]` (Improper Neutralization of Special Elements in an Expression Language)
- `cpes` — list of `cpe:2.3:a:apache:log4j:...` URIs
- `references` — NVD and vendor advisory URLs

This is factual CVE data from the graph. It can be stated directly.

**Step 3: Interpret trace_cve_to_attack result**

Check `results.cve_traces["CVE-2021-44228"]`:
- `paths` should contain one or more evidence path objects
- Each path has `steps`: e.g., CVE-2021-44228 -[Problem_Type]-> CWE-917 -[RelatedAttackPattern]-> CAPEC-94 -[Mapped_Attack]-> T1190
- `confidence`: `"knowledge_graph_mapping"` — this is a graph mapping, NOT confirmed runtime exploitation
- `limitations`: read and include ALL items verbatim

**Step 4: Interpret risk signals**

From `assessment`:
- `observed_signals`: "CVE-2021-44228 extracted from alert", "Source IP 203.0.113.42 in alert"
- `graph_context_signals`: "Knowledge graph maps CVE-2021-44228 -[Problem_Type]-> CWE-917 -[RelatedAttackPattern]-> CAPEC-94 -[Mapped_Attack]-> T1190 Exploit Public-Facing Application"
- `prioritization_signals`: "CVSS 10.0 Critical", "patch advisory in references"

**Critical distinction:**
- The IDS fired on a signature match — this is an *observed signal*, a detection event
- The ATT&CK technique T1190 comes from the knowledge graph mapping — it is NOT proof the technique succeeded
- Do NOT write "attacker used T1190" — write "IDS alert matches Log4Shell signature; knowledge graph associates CVE-2021-44228 with T1190 (Exploit Public-Facing Application) via CAPEC-94"

## Expected Response Skeleton

```
## Summary
IDS alert detected Log4Shell (CVE-2021-44228) signature targeting prod-app-01.
CVE is CVSS 10.0 Critical. Knowledge graph maps to T1190 via CWE-917 → CAPEC-94.
Exploitation is not confirmed — alert represents a detection event, not verified compromise.

## Observed Evidence
- extracted_cves: ["CVE-2021-44228"]
- asset_hint: prod-app-01 (10.0.1.50)
- observed_signals:
  - CVE-2021-44228 (Log4Shell) extracted from alert text
  - Source IP 203.0.113.42 flagged by edge-ids-01

## Knowledge Graph Context
- CVE-2021-44228: Remote code execution via JNDI injection in Apache Log4j
- CVSS v3: 10.0 Critical
- Related CWEs: CWE-917 (Expression Language Injection)
- Affected CPEs: cpe:2.3:a:apache:log4j:2.* (subset)
- graph_context_signals:
  - Knowledge graph maps CVE-2021-44228 -[Problem_Type]-> CWE-917 -[RelatedAttackPattern]-> CAPEC-94 -[Mapped_Attack]-> T1190

## Evidence Paths
Path 1:
  CVE-2021-44228 -[Problem_Type]-> CWE-917 -[RelatedAttackPattern]-> CAPEC-94 -[Mapped_Attack]-> T1190
  confidence: knowledge_graph_mapping
  Note: This path reflects knowledge graph associations (GraphKer relationship names), not observed attacker activity.

## Risk Signals
- CVSS 10.0 Critical — highest severity; patch urgently if Log4j 2.x is deployed
- prioritization_signals: patch advisory available in references

## Limitations
[Include ALL items from limitations[] verbatim, e.g.:]
- "CVE→ATT&CK mapping is derived from knowledge graph relationships, not observed telemetry."
- "CAPEC patterns describe classes of attacks, not specific exploit code."

## Recommended Next Actions
- Confirm whether prod-app-01 runs Apache Log4j 2.x (check asset inventory / SBOM)
- Validate patch status: Log4j >= 2.17.1 or mitigations applied
- Investigate source IP 203.0.113.42 — check for additional connections or lateral movement indicators
- Escalate to IR if Log4j 2.x is confirmed on prod-app-01
```
