# Example: Alert With CWE Chain

## User Input

```
WAF Alert [MEDIUM]: Request blocked — pattern matched potential CWE-692 denylist bypass
leading to reflected XSS. Endpoint: /search?q=. User-Agent suggests automated scanner.
Time: 2024-01-15T09:10:00Z
```

## Tool Sequence

1. Call `triage_alert(alert_text)` to extract entities
2. Inspect `extracted.cwes` — expected: `["CWE-692"]`
3. Call `lookup_cwe("CWE-692")` to get full weakness details, related CWE nature chain, CAPEC mappings

If the user asks about the implied XSS endpoint:
4. Call `lookup_cwe("CWE-79")` (Improper Neutralization of Input During Web Page Generation — XSS) if CWE-79 appears in related_cwes

## Expected Reasoning

**Step 1: Read triage result**

From `triage_alert`:
- `extracted.cwes`: `["CWE-692"]`
- No CVEs extracted from this alert (no CVE IDs in text)
- `observed_signals`: "CWE-692 denylist bypass pattern mentioned in alert", "WAF block event"

**Step 2: Read lookup_cwe("CWE-692") result**

Expected fields:
- `name`: "Incomplete Denylist to Cross-Site Scripting" (or similar)
- `description`: Explains why denylist-based filtering fails to prevent XSS
- `abstraction`: Variant (granular weakness)
- `related_cwes`: This is the critical section

**Step 3: Interpret all Related_Weakness Nature values**

Read every entry in `related_cwes[]`. Each entry has `nature`, `target`, `target_name`.

Nature values and their meaning:
- `ChildOf` → This CWE is a more specific instance of the parent CWE. E.g., CWE-692 ChildOf CWE-184 means CWE-692 is a specific case of incomplete denylist.
- `ParentOf` → This CWE has a child that is more specific.
- `PeerOf` → Closely related weakness at the same level.
- `CanPrecede` → This CWE can lead to another weakness in a chain.
- `CanFollow` → This CWE can result from another weakness.
- `StartsWith` → This CWE initiates a weakness chain.
- `FollowedBy` → Another weakness typically follows this one.
- `Requires` → This CWE requires another weakness to exist.
- `RequiredBy` → Another weakness requires this one.
- `CanAlsoBe` → Under different conditions, could manifest as this weakness.

**Do NOT discard any nature value.** Each one carries structural meaning about how weaknesses compose.

**Actual graph data for CWE-692:**
`lookup_cwe("CWE-692")` returns:
- `{nature: "StartsWith", target: "CWE-184", target_name: "Incomplete List of Disallowed Inputs"}` → CWE-692 initiates a chain starting from incomplete denylist
- `{nature: "ChildOf",    target: "CWE-184", target_name: "Incomplete List of Disallowed Inputs"}` → CWE-692 is a specialised case of incomplete denylist filtering

Note: `CanPrecede CWE-79` is NOT present in the current graph import. The XSS connection is
implicit in the CWE-692 name ("Incomplete Denylist to Cross-Site Scripting") and its CAPEC
mappings (CAPEC-71/80/85/120/267 — encoding bypass patterns), not via a direct CanPrecede edge.
Cite the CWE name and CAPEC list to explain the XSS path — do not fabricate a CanPrecede edge.

**Step 4: Read CAPEC mappings**

`capecs[]` entries show what attack patterns exploit this weakness. E.g.:
- CAPEC-86 (XSS Using HTTP Query Strings)
- CAPEC-198 (XSS Using Alternate Syntax)

These are attack pattern candidates — they do not mean any specific attack occurred.

**Step 5: Interpret risk signals**

- `observed_signals`: WAF blocked the request — exploitation was NOT confirmed. The alert is a block event.
- `graph_context_signals`: CWE-692 knowledge graph chain maps to XSS weakness pattern and CAPEC attack patterns.
- `prioritization_signals`: No CVSS (no CVE in this alert). Priority based on CWE severity and endpoint sensitivity.

**Critical distinction:**
The WAF alert says "pattern matched" and "blocked". This does NOT mean XSS was successful. Do not claim exploitation occurred.

## Expected Response Skeleton

```
## Summary
WAF blocked a request matching a CWE-692 denylist bypass pattern on /search?q=.
CWE-692 name is "Incomplete Denylist to Cross-Site Scripting" — XSS risk is implicit in
the weakness definition. Knowledge graph links CWE-692 to encoding-bypass CAPEC patterns.
No successful exploitation confirmed — WAF block event only.

## Observed Evidence
- extracted_cwes: ["CWE-692"]
- No CVEs extracted from alert
- observed_signals:
  - CWE-692 denylist bypass pattern matched by WAF
  - Request was blocked — no evidence of successful exploitation
  - User-Agent suggests automated scanner

## Knowledge Graph Context
CWE-692: Incomplete Denylist to Cross-Site Scripting
- Abstraction: Compound  |  Structure: Chain
- Description: [from lookup_cwe.description field]
- Related Weaknesses (all Nature values returned by graph):
  - StartsWith CWE-184 (Incomplete List of Disallowed Inputs) — CWE-692 initiates a chain from incomplete denylist filtering
  - ChildOf   CWE-184 (Incomplete List of Disallowed Inputs) — CWE-692 is a specialised case of CWE-184
  Note: No CanPrecede CWE-79 edge exists in the current graph. The XSS connection is
  expressed via the CWE-692 name and CAPEC mappings, not a direct graph edge.
- CAPEC mappings (encoding-bypass patterns): CAPEC-71, CAPEC-80, CAPEC-85, CAPEC-120, CAPEC-267
- Mitigations: [from lookup_cwe mitigations field — may be empty for this CWE]
- graph_context_signals:
  - CWE-692 is a Chain weakness initiating with CWE-184 (incomplete denylist)
  - CAPEC mappings suggest encoding-based bypass techniques consistent with alert

## Evidence Paths
No CVE present — no CVE → ATT&CK trace available.
Weakness chain from graph: CWE-692 -[StartsWith]-> CWE-184
Note: This is a knowledge graph relationship, not confirmation of a successful XSS attack.
The XSS implication comes from the CWE-692 name, not a graph edge to CWE-79.

## Risk Signals
- No CVSS score (no CVE in alert) — severity based on CWE and endpoint context
- prioritization_signals:
  - Endpoint /search?q= accepts query input — validate XSS sanitization independently
  - Automated scanner activity detected — may indicate active reconnaissance

## Limitations
- No CVE was extracted; no vulnerability-specific CVSS or patch data available.
- WAF block does not confirm exploitation was attempted by a human attacker (automated scanner indicated).
- CWE-692 has no direct CanPrecede CWE-79 edge in the current graph import; XSS risk is inferred from the weakness name and CAPEC patterns only.

## Recommended Next Actions
- Review WAF denylist rules for CWE-692 bypass patterns — test coverage of encoding variants (UTF-8, double encoding, alternate syntax)
- Test /search?q= endpoint with allowlist-based input validation (not denylist)
- Review scanner source IP for additional suspicious activity
- Consider CWE-79 mitigations: output encoding, Content Security Policy
```
