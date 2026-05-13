"""CLI entry point for SOC Triage Mode A — test without MCP client."""
from __future__ import annotations

import argparse
import json
import sys

from .neo4j_client import Neo4jClient
from .tools.lookup_cve import lookup_cve
from .tools.lookup_cwe import lookup_cwe
from .tools.trace_cve_to_attack import trace_cve_to_attack
from .tools.lookup_cpe_vulnerabilities import lookup_cpe_vulnerabilities
from .tools.schema_introspection import schema_introspection
from .triage_service import triage_alert
from .report import format_triage_report


def _out(data: object, as_report: bool = False) -> None:
    if as_report and isinstance(data, dict) and "report" in data:
        print(data["report"])
    elif as_report and isinstance(data, str):
        print(data)
    else:
        print(json.dumps(data, indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cyber-graph-triage",
        description="SOC Triage Mode A — Neo4j Cybersecurity Knowledge Graph CLI",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # triage
    p_triage = sub.add_parser("triage", help="Full SOC triage from alert text")
    p_triage.add_argument("--text", required=True, help="Alert text")
    p_triage.add_argument("--product-hint", default=None)
    p_triage.add_argument("--asset-hint", default=None)
    p_triage.add_argument("--report", action="store_true", help="Output markdown report")

    # lookup-cve
    p_cve = sub.add_parser("lookup-cve", help="Look up a CVE")
    p_cve.add_argument("cve_id", help="e.g. CVE-2021-34709")

    # lookup-cwe
    p_cwe = sub.add_parser("lookup-cwe", help="Look up a CWE")
    p_cwe.add_argument("cwe_id", help="e.g. CWE-692")

    # lookup-cpe
    p_cpe = sub.add_parser("lookup-cpe", help="Find CVEs by CPE keyword")
    p_cpe.add_argument("keyword", help="e.g. apache:struts, cisco, openssl")

    # trace
    p_trace = sub.add_parser("trace", help="Trace CVE → CWE → CAPEC → ATT&CK")
    p_trace.add_argument("cve_id")

    # schema
    sub.add_parser("schema", help="Show Neo4j labels and relationship types")

    args = parser.parse_args()
    client = Neo4jClient()

    try:
        if args.cmd == "triage":
            result = triage_alert(
                client,
                args.text,
                product_hint=args.product_hint,
                asset_hint=args.asset_hint,
                include_report=args.report,
            )
            _out(result, as_report=args.report)

        elif args.cmd == "lookup-cve":
            _out(lookup_cve(client, args.cve_id))

        elif args.cmd == "lookup-cwe":
            _out(lookup_cwe(client, args.cwe_id))

        elif args.cmd == "lookup-cpe":
            _out(lookup_cpe_vulnerabilities(client, args.keyword))

        elif args.cmd == "trace":
            _out(trace_cve_to_attack(client, args.cve_id))

        elif args.cmd == "schema":
            _out(schema_introspection(client))

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
