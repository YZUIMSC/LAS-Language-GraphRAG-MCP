# Response Policy

## Tone and Language Guidelines

This skill produces SOC triage output for security analysts. Language must be precise, conservative, and falsifiable. Vague or sensationalized claims undermine analyst trust and waste investigation resources.

**Required tone:** Analytical, evidence-bounded, actionable.

**Avoid:** Dramatic language ("attacker compromised the system"), unfounded certainty, catastrophizing based on CVSS alone.

---

## Signal Layer Separation

All triage responses must separate three epistemic layers. Never merge them.

### Layer 1: Observed Signals (`observed_signals`)

**Source:** `triage_alert.assessment.observed_signals`, or what you directly read from the alert text.

**What it represents:** Facts explicitly stated in the user's input or alert. Entities extracted by regex (CVE IDs, CWE IDs). Event data from the alert (source IP, endpoint, sensor name, timestamp).

**Language to use:**
- "Alert text states..."
- "CVE-XXXX-XXXX was extracted from the alert"
- "The IDS flagged a pattern matching..."
- "Alert includes source IP..."

**What to never say here:**
- "The attacker exploited..." (not an observation unless the alert says so)
- "The vulnerability was triggered..." (observation vs. signature match distinction)

---

### Layer 2: Knowledge Graph Context (`graph_context_signals`)

**Source:** `trace_cve_to_attack.paths`, `lookup_cwe.related_cwes`, `lookup_cwe.capecs`, `triage_alert.assessment.graph_context_signals`.

**What it represents:** Relationships derived from the knowledge graph — CVE weakness associations, CAPEC attack patterns, ATT&CK technique mappings, CWE chains.

**Language to use:**
- "Knowledge graph associates CVE-XXXX-XXXX with..."
- "Graph mapping indicates candidate technique T1190"
- "CWE-692 CanPrecede CWE-79 in the knowledge graph"
- "CAPEC-94 is a possible attack pattern for this weakness class"
- "Graph-derived association — not observed telemetry"

**What to never say here:**
- "The attacker used T1190" (technique was not observed)
- "This vulnerability enables [technique]" without noting it's a graph mapping
- "This confirms the attacker..." (graph context does not confirm anything about a specific incident)

---

### Layer 3: Prioritization Signals (`prioritization_signals`)

**Source:** `triage_alert.assessment.prioritization_signals`, CVSS scores from `lookup_cve`, severity fields.

**What it represents:** Data used to prioritize response urgency — CVSS score, severity level, patch/advisory availability, affected product count.

**Language to use:**
- "CVSS 10.0 Critical — highest severity rating"
- "Patch advisory available in references"
- "Multiple CPE products affected"
- "Prioritize investigation of this CVE"

**What to never say here:**
- "CVSS 10.0 confirms exploitation occurred" (CVSS measures severity if exploited, not exploitation likelihood)
- "This is definitely being exploited in the wild" (graph has no real-time threat intel)

---

## Overclaiming Rules (Mandatory)

These rules must be applied to every response produced using this skill.

### Rule 1: No exploitation success claims without explicit evidence
Do not state that exploitation succeeded, a system was compromised, or a payload executed unless the alert explicitly includes direct evidence (e.g., confirmed shell, confirmed data access, confirmed post-exploitation activity).

**Wrong:** "The attacker exploited CVE-2021-44228 on prod-app-01."
**Right:** "IDS signature matched CVE-2021-44228 exploit pattern. Exploitation is not confirmed."

### Rule 2: No ATT&CK technique observation claims from graph mapping alone
Do not claim a specific ATT&CK technique "was used" solely because `trace_cve_to_attack` returned that technique.

**Wrong:** "The attacker used T1190 (Exploit Public-Facing Application)."
**Right:** "Knowledge graph associates CVE-2021-44228 with T1190 via CAPEC-94. This is a graph mapping, not an observed technique."

### Rule 3: No confirmed asset vulnerability from CPE keyword results
Do not claim a specific asset or deployment is confirmed vulnerable based on `lookup_cpe_vulnerabilities` results.

**Wrong:** "Your Apache Struts deployment is vulnerable to these CVEs."
**Right:** "CPE keyword match found these CVEs associated with 'apache:struts'. Validate against your specific deployed version. Results are substring matches, not confirmed inventory exposure."

### Rule 4: CVSS score is severity, not exploitation confirmation
Do not use CVSS High/Critical as a proxy for "this is actively exploited" or "this was used in this incident."

**Wrong:** "CVSS 9.8 — this vulnerability is being actively exploited."
**Right:** "CVSS 9.8 Critical — high severity if exploited. Prioritize patching."

### Rule 5: Surface all warnings, limitations, errors, and truncated flags
Never omit these fields. They exist to bound the claims made in the response.

- If `limitations[]` is non-empty → include all items verbatim
- If `warnings[]` is non-empty → include all items verbatim
- If `truncated=True` → note results are capped
- If `error` is present → report the error and stop; do not fabricate results
- If `health_warnings[]` is non-empty → include them in the response

---

## Handling Insufficient Data

When graph data is missing, partial, or the CVE/CWE is not found:

| Situation | Correct response |
|---|---|
| `found=False`, no error | "CVE/CWE not found in knowledge graph. No graph-derived context available." |
| `found=False`, error present | "Query failed: [error message]. Check Neo4j connectivity." |
| `paths` empty, `warnings` non-empty | Quote warnings. State: "No evidence path found." Do not fabricate path. |
| `node_counts["CVE"] = 0` | "Graph has no CVE data. Run data import pipeline before querying." |
| `capecs` empty in lookup_cwe | "No CAPEC mappings found for this CWE in the graph." |
| `truncated=True` | "Results capped at [limit]. Additional CVEs may exist — refine keyword or increase limit." |

Standard phrase for missing data:
> "Insufficient data in the knowledge graph to make this determination. [specific field] was not found."

---

## Remediation Recommendation Policy

All remediation recommendations must be:
- **Verification-oriented**: suggest confirming, patching, isolating, escalating — not destroying or blocking without review
- **Conditional**: "If version X is confirmed, apply patch Y" — not blanket commands
- **Non-destructive**: never recommend `rm`, kill -9`, firewall block, or service shutdown without explicit human review authorization

**Good examples:**
- "Confirm whether Log4j 2.x is in the SBOM for prod-app-01"
- "Validate patch status: Log4j >= 2.17.1 required"
- "Escalate to IR if asset is confirmed affected"
- "Isolate the asset pending investigation if exploitation is confirmed"

**Bad examples:**
- "Block IP 203.0.113.42 at the perimeter" (unilateral action without investigation)
- "Delete the application until patched" (destructive)
- "Shut down the service" (service disruption without authorization)
