"""MCP server entrypoint for Cybersecurity Knowledge Graph SOC Triage."""
from __future__ import annotations

import argparse
from typing import Any

import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from mcp.server import Server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from cyber_graph_triage.neo4j_client import Neo4jClient
from cyber_graph_triage.tools.lookup_cve import lookup_cve as _lookup_cve
from cyber_graph_triage.tools.lookup_cwe import lookup_cwe as _lookup_cwe
from cyber_graph_triage.tools.trace_cve_to_attack import trace_cve_to_attack as _trace
from cyber_graph_triage.tools.lookup_cpe_vulnerabilities import lookup_cpe_vulnerabilities as _lookup_cpe
from cyber_graph_triage.tools.schema_introspection import schema_introspection as _schema
from cyber_graph_triage.triage_service import triage_alert as _triage_alert

mcp = FastMCP("cyber-graph-triage")

_client = Neo4jClient()


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Look up CVE details, related CWE, affected CPEs, CVSS scores, and references
    from the Neo4j cybersecurity knowledge graph."""
    return _lookup_cve(_client, cve_id)


@mcp.tool()
async def lookup_cwe(cwe_id: str) -> dict[str, Any]:
    """Look up CWE details, related weakness relationships (all Nature values),
    CAPEC mappings, mitigations, and consequences from the Neo4j knowledge graph."""
    return _lookup_cwe(_client, cwe_id)


@mcp.tool()
async def trace_cve_to_attack(cve_id: str) -> dict[str, Any]:
    """Trace evidence paths from a CVE to CWE, CAPEC, and ATT&CK techniques.
    Returns paths and warnings if ATT&CK mapping is not found."""
    return _trace(_client, cve_id)


@mcp.tool()
async def lookup_cpe_vulnerabilities(keyword: str, limit: int = 100) -> dict[str, Any]:
    """Find CVEs affecting CPE URIs that contain a product or vendor keyword.
    Results are sorted by CVSS score descending. Keyword must be at least 3 characters.
    Use specific terms e.g. 'apache:struts', 'cisco:ios_xr', 'openssl'.
    Returns truncated=true when there are more results than the limit."""
    return _lookup_cpe(_client, keyword, limit=limit)


@mcp.tool()
async def triage_alert(
    alert_text: str,
    product_hint: str | None = None,
    asset_hint: str | None = None,
    include_report: bool = False,
) -> dict[str, Any]:
    """Perform deterministic SOC triage for an alert text.
    Extracts CVE/CWE entities, queries the Neo4j cybersecurity graph, and returns
    a structured triage result. Set include_report=true for a markdown report."""
    return _triage_alert(_client, alert_text, product_hint, asset_hint, include_report)


@mcp.tool()
async def schema_introspection() -> dict[str, Any]:
    """Return Neo4j labels and relationship types to debug GraphKer schema compatibility."""
    return _schema(_client)


def create_starlette_app(mcp_server: Server, *, debug: bool = False) -> Starlette:
    """Create a Starlette app serving the MCP server over SSE transport."""
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(
            request.scope,
            request.receive,
            request._send,  # noqa: SLF001
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    async def handle_health(request: Request) -> JSONResponse:
        return JSONResponse({"status": "ok", "server": "cyber-graph-triage"})

    return Starlette(
        debug=debug,
        routes=[
            Route("/health", endpoint=handle_health),
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Graph Triage MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if args.transport == "sse":
        mcp_server = mcp._mcp_server  # noqa: SLF001
        starlette_app = create_starlette_app(mcp_server, debug=args.debug)
        uvicorn.run(starlette_app, host=args.host, port=args.port)
    else:
        mcp.run(transport="stdio")
