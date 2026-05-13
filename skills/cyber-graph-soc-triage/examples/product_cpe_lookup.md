# Example: Product CPE Lookup

## User Input

```
Can you check what CVEs affect Apache Struts? We have Struts 2.x deployed in our
application server farm. I want to know the high/critical ones.
```

## Tool Sequence

1. Extract keyword from user input: `"apache:struts"` (specific enough, >= 3 chars)
2. Call `lookup_cpe_vulnerabilities(keyword="apache:struts", limit=100)`
3. If `truncated=True`, note results are capped and suggest refining with a version-specific keyword
4. Filter or sort results by `score` descending to surface High/Critical CVEs

## Expected Reasoning

**Step 1: Validate keyword**

The keyword `"apache:struts"` is 13 characters — passes the minimum 3-character check.
Prefer vendor:product format (e.g., `"apache:struts"`) over generic terms like `"struts"` alone to reduce noise.

**Step 2: Read lookup_cpe_vulnerabilities result**

Key fields:
- `keyword`: `"apache:struts"` — confirms what was searched
- `count`: number of results returned
- `truncated`: if `True`, there are more CVEs beyond the limit
- `warning`: **always present** — read it: *"Results are based on substring match of CPE URI strings, not a precise CPE inventory match. Validate affected assets separately."*
- `results`: list of CVE entries, each with `cve`, `cpe`, `vulnerable`, `score`, `severity`, `cwes`

**Step 3: Interpret results correctly**

The `warning` field carries a mandatory constraint:

> Results are based on substring match of CPE URI strings, not a precise CPE inventory match. Validate affected assets separately.

This means:
- A CVE appearing in results means its CPE URI contains `"apache:struts"` as a substring
- It does NOT mean the specific version in your application server is confirmed vulnerable
- It does NOT mean your asset is exposed — that requires cross-referencing with actual inventory
- A result with `vulnerable=True` means the CPE relationship in the graph is marked vulnerable, but you must still verify the exact version match

**Step 4: Handle truncation**

If `truncated=True`:
- Results were capped at `limit` (default 100)
- More CVEs may exist for this keyword
- Suggest: use a more specific keyword (e.g., `"apache:struts:2.5"` or specific version) or increase limit

**Step 5: Surface High/Critical CVEs**

Sort or filter results where `severity` is `"HIGH"` or `"CRITICAL"` (or `score >= 7.0`).
For each significant CVE, you may subsequently call `lookup_cve(cve_id)` or `trace_cve_to_attack(cve_id)` for deeper context.

**What NOT to say:**
- Do NOT say "your application server is vulnerable to these CVEs" — you have no inventory confirmation
- Do NOT say "Apache Struts 2.x is vulnerable" as a blanket statement — versions vary
- Do NOT ignore the `warning` field — surface it explicitly

## Expected Response Skeleton

```
## Summary
Searched for CVEs associated with CPE URIs containing "apache:struts".
Found [count] results (truncated: [true/false]). Results are candidate matches only —
not a confirmed inventory match for your specific Struts 2.x deployment.

## Observed Evidence
- User query: Apache Struts 2.x deployment
- Keyword searched: "apache:struts"
- Asset context: application server farm (no specific version or CPE confirmed)

## Knowledge Graph Context
CPE substring match results for "apache:struts":

High/Critical CVEs (score >= 7.0):
| CVE | Score | Severity | CWEs | CPE (sample) |
|-----|-------|----------|------|--------------|
| CVE-XXXX-XXXX | 10.0 | CRITICAL | [CWE-20] | cpe:2.3:a:apache:struts:2.5.12:... |
| CVE-YYYY-YYYY | 9.8  | CRITICAL | [CWE-434] | cpe:2.3:a:apache:struts:2.3.x:... |
| ...           | ...  | ...      | ...  | ... |

[If truncated=True:] Note: Results capped at [limit]. Additional CVEs may exist.

Important: [Surface the warning field verbatim]
"Results are based on substring match of CPE URI strings, not a precise CPE inventory match. Validate affected assets separately."

## Evidence Paths
Not applicable for CPE lookup — call lookup_cve(cve_id) or trace_cve_to_attack(cve_id)
for specific CVEs of interest to get evidence paths.

## Risk Signals
- prioritization_signals:
  - [N] Critical CVEs and [M] High CVEs found for apache:struts
  - Top CVE by score: CVE-XXXX-XXXX (CVSS 10.0)
  - Versions in CPE URIs: [list distinct versions found]

## Limitations
- Results are CPE URI substring matches, not confirmed inventory exposure.
- The graph may not contain all CVEs for this product (depends on data import date).
- Specific vulnerability applicability depends on your exact Struts version and configuration.
[If truncated=True:]
- Results truncated at [limit] — additional CVEs exist; refine keyword or increase limit.

## Recommended Next Actions
- Identify exact Apache Struts version(s) deployed in your application server farm
- Cross-reference deployed version against CPE URIs in top CVE results
- Prioritize patching CVEs with CVSS >= 9.0 if deployed version matches
- Consider calling lookup_cve("CVE-XXXX-XXXX") for the top Critical CVEs for patch references
```
