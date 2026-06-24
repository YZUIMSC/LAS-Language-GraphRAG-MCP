"""CLI entry point for SOC Triage Mode A — test without MCP client."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .bridge_manager import auto_start_ws_bridge_from_env
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

    # ── read-only triage tools ────────────────────────────────────────────────

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

    # ── data-patch tools (write, CLI-only, not exposed as MCP tools) ─────────

    # import-cwe-chain-components
    p_import = sub.add_parser(
        "import-cwe-chain-components",
        help="Patch missing CWE chain component relationships into Neo4j (write)",
    )
    p_import.add_argument(
        "--file",
        required=True,
        metavar="PATH",
        help="JSON patch file (default: cyber_graph_triage/data/cwe_chain_components_patch.json)",
    )
    p_import.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and show plan without writing to Neo4j",
    )
    p_import.add_argument(
        "--allow-create-placeholder",
        action="store_true",
        help="Create a stub CWE node if the target does not exist (default: skip with warning)",
    )

    # validate-cwe-chain
    p_validate = sub.add_parser(
        "validate-cwe-chain",
        help="Show Related_Weakness natures for a CWE and check expected chain relations",
    )
    p_validate.add_argument("cwe_id", help="e.g. CWE-692")
    p_validate.add_argument(
        "--patch-file",
        default=None,
        metavar="PATH",
        help="Patch file to compare against (default: built-in patch file)",
    )

    args = parser.parse_args()
    with auto_start_ws_bridge_from_env():
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

            elif args.cmd == "import-cwe-chain-components":
                _cmd_import(client, args)

            elif args.cmd == "validate-cwe-chain":
                _cmd_validate(client, args)

        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        finally:
            client.close()


def _cmd_import(client: Neo4jClient, args: argparse.Namespace) -> None:
    from .importers.cwe_chain_components import load_patch_file, run_import

    patch_path = Path(args.file)
    if not patch_path.exists():
        print(f"Error: file not found: {patch_path}", file=sys.stderr)
        sys.exit(1)

    try:
        entries = load_patch_file(patch_path)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    result = run_import(
        client,
        entries,
        dry_run=args.dry_run,
        allow_create_placeholder=args.allow_create_placeholder,
        input_file=str(patch_path),
    )
    _out(result)
    if result["skipped"] > 0:
        sys.exit(2)


def _cmd_validate(client: Neo4jClient, args: argparse.Namespace) -> None:
    from .importers.cwe_chain_components import validate_chain

    patch_file = Path(args.patch_file) if args.patch_file else None
    result = validate_chain(client, args.cwe_id, patch_file=patch_file)
    _out(result)
    if result.get("warnings"):
        sys.exit(2)


if __name__ == "__main__":
    main()
