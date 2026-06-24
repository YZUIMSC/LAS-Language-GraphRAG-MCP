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

`NEO4J_URI` is passed directly to the official Neo4j Python driver. Supported
schemes are `bolt://`, `bolt+s://`, `bolt+ssc://`, `neo4j://`, `neo4j+s://`,
and `neo4j+ssc://`. Do not set `NEO4J_URI` to `ws://` or `wss://`; the Python
driver does not accept WebSocket URIs.

For a remote Bolt-over-WebSocket endpoint, use the local bridge described in
[Experimental Bolt-over-WebSocket Bridge](#experimental-bolt-over-websocket-bridge).
In that mode, `NEO4J_URI` still points to a local `bolt://` listener.

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

## Experimental Bolt-over-WebSocket Bridge

This repo includes an experimental local TCP-to-WebSocket bridge for deployments
where Neo4j is reachable through a WebSocket endpoint, such as a Cloudflare or
Nginx setup originally intended for Neo4j Browser.

The bridge keeps the Python Neo4j driver on a normal local Bolt TCP URI:

```
NEO4J_WS_BRIDGE_TARGET=wss://graphker.lab.114514.my.id:443/
NEO4J_WS_BRIDGE_LISTEN_HOST=127.0.0.1
NEO4J_WS_BRIDGE_LISTEN_PORT=17687
```

When `NEO4J_WS_BRIDGE_TARGET` is set, the MCP server and CLI start the bridge
automatically, rewrite `NEO4J_URI` in the current process to the local bridge
listener, and shut the bridge down when the process exits. Run the MCP server
or CLI as usual:

```bash
uv run python -m cyber_graph_triage.cli schema
uv run python server.py --transport stdio
```

For debugging, the bridge can still be started manually:

```bash
uv run neo4j-ws-bolt-bridge
```

Data flow:

```
Neo4j Python driver
  -> local TCP 127.0.0.1:17687
  -> cyber_graph_triage.ws_bolt_bridge
  -> remote wss:// endpoint
  -> WebSocket-to-Bolt proxy
  -> Neo4j Bolt endpoint
```

This bridge assumes the remote WebSocket endpoint forwards binary WebSocket
payloads directly to Neo4j Bolt. If your gateway requires a specific path,
Cloudflare Access token, custom headers, or WebSocket subprotocol, the current
bridge must be extended before it will work.

### Docker Compose

Direct Bolt mode is unchanged:

```bash
docker compose up -d --build cyber-graph-triage
```

For WebSocket bridge mode, set `NEO4J_WS_BRIDGE_TARGET` and start the same
service. The Python server process starts the bridge automatically and rewrites
`NEO4J_URI` inside the process to the local bridge listener:

```bash
NEO4J_WS_BRIDGE_TARGET=wss://graphker.lab.114514.my.id:443/ \
docker compose up -d --build cyber-graph-triage
```

No separate Compose service is required. If `NEO4J_WS_BRIDGE_TARGET` is unset,
the service uses `NEO4J_URI` normally.

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
  ws_bolt_bridge.py                # Experimental local TCP-to-WebSocket bridge
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
  test_config.py
  test_extractors.py
  test_report.py
  test_ws_bolt_bridge.py
```

---

## Known Limitations (v0.1)

- **No free Text2Cypher** — all queries are fixed and deterministic (Mode A only).
- **ATT&CK mapping** depends on the presence of Technique nodes and their relationships in your graph. The server attempts several label/relationship name combinations and warns if none found.
- **Asset context** — no Asset nodes in the base schema; CPE-based lookup requires a `product_hint`.
- **No attack success assertion** — CAPEC/ATT&CK mappings indicate *possible* attack patterns, not confirmed observed techniques.
- **CPE keyword search** is substring-based; a graph with millions of CPE nodes may need indexing on `cpe.uri`.
- **WebSocket bridge is experimental** — it is a local transport adapter for
  environments that already expose raw Bolt bytes through WebSocket binary
  frames. It is not a replacement for the Neo4j Python driver.
