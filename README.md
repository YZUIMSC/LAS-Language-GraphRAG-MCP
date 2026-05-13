# Cybersecurity Knowledge Graph — SOC Triage Mode (Mode A)

A Python PoC that exposes a **deterministic, fixed-Cypher** SOC triage capability over a Neo4j cybersecurity knowledge graph (GraphKer-style schema) as an **MCP server**. LLM agents (Claude Desktop, Cursor, OpenWebUI, etc.) can call the tools directly; a CLI is also provided for testing.

---

## Why MCP-first

```
MCP client (Claude / agent)
        ↓  MCP tool call
  server.py  (FastMCP adapter)
        ↓
  TriageTools / TriageService   ← same code used by CLI & tests
        ↓
  Neo4jClient
        ↓
  Neo4j knowledge graph
```

Core logic lives in `cyber_graph_triage/` and is **independent of MCP**. The MCP server is a thin async wrapper. This means unit tests, the CLI, and the MCP server all exercise the same code path.

---

## GraphRAG Modes

| Mode | Description | This repo |
|------|-------------|-----------|
| **A — Fixed Queries** | Deterministic Cypher, high reliability | **This PoC** |
| B — Controlled Exploration | Guided graph traversal, semantic search | Future |
| C — Guarded Text2Cypher | LLM-generated Cypher with guardrails | Future |

---

## Neo4j Schema Assumptions (GraphKer)

The queries assume GraphKer-style labels and relationships. Use `schema_introspection` to verify your graph:

| Label | Description |
|-------|-------------|
| `CVE` | Vulnerability record |
| `CWE` | Weakness type |
| `CPE` | Affected platform/product |
| `CAPEC` | Attack pattern |
| `CVSS_3` / `CVSS_2` | Score nodes |
| `Reference_Data` | Advisory / patch references |
| `Mitigation` | Remediation guidance |
| `Consequence` | Impact scope |
| `Technique` / `ATTACK_Technique` | ATT&CK technique (any label variant) |

Key relationships: `Problem_Type`, `applicableIn`, `CVSS3_Impact`, `CVSS2_Impact`,
`referencedBy`, `Related_Weakness`, `RelatedAttackPattern`, `hasMitigation`, `hasConsequence`.

All queries use `OPTIONAL MATCH` and gracefully handle missing nodes/relationships.

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=change-me
NEO4J_DATABASE=neo4j
```

> Never commit real credentials to the repo.

---

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env        # then edit .env
```

---

## MCP Server

### stdio (default — for Claude Desktop, Cursor, etc.)

```bash
python server.py --transport stdio
```

### SSE (for browser-based clients, OpenWebUI)

```bash
python server.py --transport sse --host 0.0.0.0 --port 8080
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `lookup_cve` | CVE details, CVSS, CWEs, CPEs, references |
| `lookup_cwe` | CWE details, all Related_Weakness Nature values, CAPEC, mitigations |
| `trace_cve_to_attack` | CVE → CWE → CAPEC → ATT&CK evidence paths |
| `lookup_cpe_vulnerabilities` | CVEs by product/vendor CPE keyword |
| `triage_alert` | Full SOC triage from alert text |
| `schema_introspection` | Debug: list Neo4j labels and relationship types |

---

## MCP Client Configuration

### Claude Desktop / Claude Code

Add to your MCP client config (e.g. `~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cyber-graph-triage": {
      "command": "python",
      "args": [
        "/absolute/path/to/server.py",
        "--transport",
        "stdio"
      ],
      "env": {
        "NEO4J_URI": "bolt://localhost:7687",
        "NEO4J_USER": "neo4j",
        "NEO4J_PASSWORD": "change-me",
        "NEO4J_DATABASE": "neo4j"
      }
    }
  }
}
```

Or using the venv Python explicitly:

```json
{
  "mcpServers": {
    "cyber-graph-triage": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": ["/absolute/path/to/server.py", "--transport", "stdio"]
    }
  }
}
```

---

## CLI Usage

```bash
# Full triage with markdown report
python -m cyber_graph_triage.cli triage \
  --text "Possible exploitation of CVE-2021-34709 observed on Cisco device" \
  --report

# Triage with product hint
python -m cyber_graph_triage.cli triage \
  --text "Potential CWE-692 denylist bypass leading to XSS" \
  --product-hint "apache:struts" \
  --report

# Lookup individual CVE
python -m cyber_graph_triage.cli lookup-cve CVE-2021-34709

# Lookup CWE (all Related_Weakness Nature values returned)
python -m cyber_graph_triage.cli lookup-cwe CWE-692

# Find CVEs by CPE keyword
python -m cyber_graph_triage.cli lookup-cpe apache:struts

# Trace CVE → CWE → CAPEC → ATT&CK
python -m cyber_graph_triage.cli trace CVE-2021-34709

# Check graph schema compatibility
python -m cyber_graph_triage.cli schema
```

---

## Running Tests

```bash
pytest tests/ -v
```

Unit tests do **not** require a running Neo4j instance. Integration tests (if added) should be marked `pytest.mark.integration` and skipped by default.

---

## Project Structure

```
server.py                          # MCP server entrypoint (FastMCP)
cyber_graph_triage/
  config.py                        # Env var loading
  neo4j_client.py                  # Neo4j driver wrapper (lazy init)
  extractors.py                    # CVE/CWE/CPE regex extractors
  schemas.py                       # Pydantic models
  triage_service.py                # Orchestrates triage flow
  report.py                        # Markdown report formatter
  cli.py                           # CLI entry point
  tools/
    lookup_cve.py
    lookup_cwe.py
    trace_cve_to_attack.py
    lookup_cpe_vulnerabilities.py
    schema_introspection.py
  cypher/                          # Cypher queries (GraphKer schema)
    lookup_cve_graphker.cypher
    lookup_cwe_graphker.cypher
    trace_cve_to_attack_graphker.cypher
    lookup_cpe_vulnerabilities_graphker.cypher
tests/
  test_extractors.py
  test_report.py
```

---

## Known Limitations (v0.1)

- **No free Text2Cypher** — all queries are fixed and deterministic (Mode A only).
- **ATT&CK mapping** depends on the presence of Technique nodes and their relationships in your graph. The server attempts several label/relationship name combinations and warns if none found.
- **Asset context** — no Asset nodes in the base schema; CPE-based lookup requires a `product_hint`.
- **No attack success assertion** — CAPEC/ATT&CK mappings indicate *possible* attack patterns, not confirmed observed techniques.
- **CPE keyword search** is substring-based; a graph with millions of CPE nodes may need indexing on `cpe.uri`.
