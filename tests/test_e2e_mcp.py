"""E2E tests: spin up the MCP stdio server and call each tool via MCP client.

These tests work whether or not a real Neo4j instance is reachable:
  - If Neo4j is available: assert the response has correct structure + found=True
  - If Neo4j is unavailable: assert graceful error (found=False, error key present)

Each test manages its own client lifecycle to avoid anyio task-group teardown
conflicts with pytest-asyncio.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_SERVER = str(Path(__file__).parent.parent / "server.py")
_PARAMS = StdioServerParameters(command=sys.executable, args=[_SERVER, "--transport", "stdio"])

_EXPECTED_TOOLS = {
    "lookup_cve",
    "lookup_cwe",
    "trace_cve_to_attack",
    "lookup_cpe_vulnerabilities",
    "triage_alert",
    "schema_introspection",
}


def _parse(result) -> dict | list:
    assert not result.isError, f"Tool raised MCP error: {result.content}"
    assert result.content, "Empty content returned by tool"
    return json.loads(result.content[0].text)


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tool_discovery():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            names = {t.name for t in result.tools}
            assert _EXPECTED_TOOLS.issubset(names), f"Missing tools: {_EXPECTED_TOOLS - names}"


# ---------------------------------------------------------------------------
# lookup_cve — assert correct structure; found=True if Neo4j up, False if not
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_cve():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            data = _parse(await session.call_tool("lookup_cve", {"cve_id": "CVE-2021-34709"}))
            assert isinstance(data, dict)
            assert "found" in data
            assert data["cve"] == "CVE-2021-34709"
            if data["found"]:
                assert isinstance(data.get("description"), str)
                assert isinstance(data.get("cwes"), list)
                assert isinstance(data.get("cpes"), list)
                assert isinstance(data.get("cvss3"), list)
            else:
                assert "error" in data


# ---------------------------------------------------------------------------
# lookup_cwe — assert correct structure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_cwe():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            data = _parse(await session.call_tool("lookup_cwe", {"cwe_id": "CWE-347"}))
            assert isinstance(data, dict)
            assert "found" in data
            assert "CWE-347" in data["cwe"]
            if data["found"]:
                assert isinstance(data.get("related_cwes"), list)
                assert isinstance(data.get("capecs"), list)
                assert isinstance(data.get("consequences"), list)
            else:
                assert "error" in data


# ---------------------------------------------------------------------------
# trace_cve_to_attack — assert structure; ATT&CK present for CVE-2023-5457
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_trace_cve_to_attack():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            data = _parse(await session.call_tool("trace_cve_to_attack", {"cve_id": "CVE-2023-5457"}))
            assert isinstance(data, dict)
            assert "found" in data
            assert isinstance(data["warnings"], list)
            assert isinstance(data["paths"], list)
            if data["found"]:
                attack_paths = [p for p in data["paths"] if p.get("attack")]
                assert len(attack_paths) >= 1, "CVE-2023-5457 should map to ATT&CK via CAPEC-439"
                assert attack_paths[0]["attack"]["id"] is not None


# ---------------------------------------------------------------------------
# lookup_cpe_vulnerabilities — assert envelope structure
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_lookup_cpe_vulnerabilities():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            data = _parse(await session.call_tool("lookup_cpe_vulnerabilities", {"keyword": "apache:struts"}))
            assert isinstance(data, dict)
            assert data["keyword"] == "apache:struts"
            assert "results" in data
            assert isinstance(data["results"], list)
            if data["results"] and "error" not in data["results"][0]:
                row = data["results"][0]
                assert "cve" in row
                assert "cpe" in row


# ---------------------------------------------------------------------------
# triage_alert — no Neo4j → structured result with report
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_triage_alert_no_neo4j():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            data = _parse(await session.call_tool("triage_alert", {
                "alert_text": "Possible exploitation of CVE-2021-34709 on Cisco device",
                "include_report": True,
            }))
            assert isinstance(data, dict)
            assert data["mode"] == "SOC_TRIAGE"
            assert "CVE-2021-34709" in data["extracted"]["cves"]
            assert "report" in data
            assert "SOC Triage Report" in data["report"]
            assert isinstance(data["assessment"]["risk_signals"], list)
            assert isinstance(data["assessment"]["limitations"], list)


# ---------------------------------------------------------------------------
# schema_introspection — no Neo4j → error key (no crash)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_schema_introspection_no_neo4j():
    async with stdio_client(_PARAMS) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            data = _parse(await session.call_tool("schema_introspection", {}))
            assert isinstance(data, dict)
            assert "error" in data or "labels" in data, (
                "Expected either 'error' (no Neo4j) or 'labels' (connected)"
            )
