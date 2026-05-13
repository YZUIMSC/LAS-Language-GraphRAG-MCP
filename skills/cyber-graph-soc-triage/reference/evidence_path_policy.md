# Evidence Path Policy

## What is an Evidence Path?

An evidence path is a structured graph traversal result returned by `trace_cve_to_attack`. It shows the chain of knowledge graph relationships connecting a CVE to ATT&CK through CWE and CAPEC.

Evidence paths answer: "What attack patterns does the knowledge graph associate with this vulnerability?"

They do NOT answer: "Was this attack technique used in this incident?"

---

## Schema of a Single Evidence Path

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
  ],
  "cwe": "CWE-1269",
  "cwe_name": "Product Released in Non-Release Configuration",
  "capec": "CAPEC-439",
  "capec_name": "Manipulation During Distribution",
  "attack": {
    "id": "1195",
    "name": "T1195 - Supply Chain Compromise",
    "relation": "Mapped_Attack"
  }
}
```

---

## Reading the `steps` Array

The `steps` array alternates between node objects and relationship objects:

- **Node object**: `{"label": "CVE" | "CWE" | "CAPEC" | "ATTACK", "id": "...", "name": "..."}`
  - `label`: the node type in the graph
  - `id`: the identifier (e.g., `"CVE-2021-44228"`, `"CWE-917"`, `"CAPEC-94"`, `"T1190"`)
  - `name`: human-readable name (optional, may be absent)
- **Relationship object**: `{"relationship": "Problem_Type" | "RelatedAttackPattern" | "Mapped_Attack" | ...}`
  - Represents the edge type connecting adjacent nodes
  - GraphKer relationship names used in this graph:
    - `Problem_Type` — CVE → CWE
    - `RelatedAttackPattern` — CWE → CAPEC
    - `Mapped_Attack` — CAPEC → ATTACK

**Reading a complete path:**
```
CVE-2023-5457 --[Problem_Type]--> CWE-1269 --[RelatedAttackPattern]--> CAPEC-439 --[Mapped_Attack]--> T1195
```

In your response, summarize the path in this inline notation. Do not drop intermediate nodes.

---

## The `confidence` Field

`confidence: "knowledge_graph_mapping"` is always this exact string for paths from `trace_cve_to_attack`.

**What it means:**
- A path was found in the Neo4j knowledge graph
- The graph contains a documented relationship from CVE through to this ATT&CK technique
- The relationship is based on CVE/CWE/CAPEC/ATT&CK taxonomic data (e.g., NVD, MITRE)

**What it does NOT mean:**
- The ATT&CK technique was observed in this incident
- The exploitation was successful
- A specific threat actor used this technique
- The path represents runtime telemetry or behavioral detection

---

## The `limitations` Field

`limitations` is a list of strings. It is mandatory context for every evidence path. You MUST include all limitations in your response.

**Why limitations matter:**
Limitations communicate the epistemic boundary of the graph mapping. Omitting them gives the reader a false sense of certainty about attacker behavior.

**Example limitations and how to handle them:**

| Limitation text | How to handle |
|---|---|
| "CVE→ATT&CK mapping is derived from knowledge graph relationships, not observed telemetry." | State this in your response before citing the technique |
| "CAPEC patterns describe classes of attacks, not specific exploit code." | Do not equate CAPEC with a confirmed exploit |
| "ATT&CK mapping not found — only CVE→CWE→CAPEC path available." | Only cite CAPEC; do not extrapolate ATT&CK technique |

---

## The `warnings` Field

`warnings` is returned at the top-level of `trace_cve_to_attack`, separate from per-path `limitations`.

`warnings` appear when:
- The CVE has no CAPEC or ATT&CK mapping in the graph (partial path only)
- The CVE was found but has no CWE in the graph (path cannot be built)
- The graph structure is incomplete for this CVE

When `warnings` is non-empty and `paths` is empty or sparse, report the warning verbatim. Do not fabricate a path.

---

## How to Cite Evidence Paths in a Response

**Correct:**
```
Knowledge graph maps CVE-2023-5457 -[Problem_Type]-> CWE-1269 -[RelatedAttackPattern]->
CAPEC-439 -[Mapped_Attack]-> T1195 (Supply Chain Compromise).
confidence: knowledge_graph_mapping — this is a graph association, not an observed technique.
Limitations: [quote limitations verbatim]
```

**Incorrect — overclaiming:**
```
The attacker used T1195 to exploit CVE-2023-5457.
```

**Incorrect — underciting (dropping the path):**
```
The CVE may relate to ATT&CK techniques.
```

**Correct when path is partial (CAPEC found, no ATT&CK):**
```
Knowledge graph maps CVE-XXXX-XXXX -[Problem_Type]-> CWE-YYY -[RelatedAttackPattern]-> CAPEC-ZZZ.
No ATT&CK technique mapping found for this path (Mapped_Attack edge absent in graph).
warnings: [quote warnings field]
```

---

## Backward-Compat Flat Fields

`trace_cve_to_attack` also returns flat fields: `cwe`, `cwe_name`, `capec`, `capec_name`, `attack`.

These exist for backward compatibility with older callers. They represent the same data as `steps` but flattened.

Prefer using `paths[*].steps` for structured output. Flat fields may be used for quick summary display.

---

## When No Path Is Found

If `paths` is empty:
- Do not synthesize a path from external knowledge
- Do not guess or add ATT&CK technique IDs based on CWE descriptions
- Report: "No evidence path found for [CVE ID] in the knowledge graph."
- Quote `warnings` field verbatim

The absence of a path does not mean the CVE is safe — it means the graph does not have the mapping. Advise looking up MITRE CVE/CWE/CAPEC/ATT&CK data manually if needed.
