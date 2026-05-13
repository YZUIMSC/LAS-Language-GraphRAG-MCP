from __future__ import annotations

from typing import Any

from .extractors import extract_cves, extract_cwes, extract_cpe_keywords
from .neo4j_client import Neo4jClient
from .tools.lookup_cve import lookup_cve
from .tools.lookup_cwe import lookup_cwe
from .tools.trace_cve_to_attack import trace_cve_to_attack
from .tools.lookup_cpe_vulnerabilities import lookup_cpe_vulnerabilities
from .report import format_triage_report


def triage_alert(
    client: Neo4jClient,
    alert_text: str,
    product_hint: str | None = None,
    asset_hint: str | None = None,
    include_report: bool = False,
) -> dict[str, Any]:
    cves = extract_cves(alert_text)
    cwes = extract_cwes(alert_text)
    cpe_keywords = extract_cpe_keywords(alert_text, product_hint)

    cve_results: dict[str, Any] = {}
    cve_traces: dict[str, Any] = {}
    for cve_id in cves:
        cve_results[cve_id] = lookup_cve(client, cve_id)
        cve_traces[cve_id] = trace_cve_to_attack(client, cve_id)

    cwe_results: dict[str, Any] = {}
    for cwe_id in cwes:
        cwe_results[cwe_id] = lookup_cwe(client, cwe_id)

    product_vulns: list[dict] = []
    for kw in cpe_keywords:
        result = lookup_cpe_vulnerabilities(client, kw)
        if "results" in result:
            product_vulns.extend(result["results"])
        else:
            product_vulns.append(result)

    evidence_paths = _collect_evidence_paths(cve_traces)
    assessment = _assess(cve_results, cwe_results, cve_traces, product_vulns, cves, cwes, alert_text)

    result: dict[str, Any] = {
        "mode": "SOC_TRIAGE",
        "input": {
            "alert_text": alert_text,
            "product_hint": product_hint,
            "asset_hint": asset_hint,
        },
        "extracted": {
            "cves": cves,
            "cwes": cwes,
            "product_hint": product_hint,
            "asset_hint": asset_hint,
        },
        "results": {
            "cves": cve_results,
            "cve_traces": cve_traces,
            "cwes": cwe_results,
            "product_vulnerabilities": product_vulns,
        },
        "assessment": assessment,
        "evidence_paths": evidence_paths,
    }

    if include_report:
        result["report"] = format_triage_report(result)

    return result


def _collect_evidence_paths(cve_traces: dict[str, Any]) -> list[dict[str, Any]]:
    paths = []
    for _cve_id, trace in cve_traces.items():
        for p in trace.get("paths", []):
            if p.get("cwe") or p.get("capec"):
                paths.append(p)
    return paths


def _assess(
    cve_results: dict,
    cwe_results: dict,
    cve_traces: dict,
    product_vulns: list,
    cves: list,
    cwes: list,
    alert_text: str,
) -> dict[str, Any]:
    # Layer 1 — extracted directly from alert input
    observed_signals: list[str] = []
    if cves:
        observed_signals.append(f"Alert text contains CVE reference(s): {', '.join(cves)}")
    if cwes:
        observed_signals.append(f"Alert text contains CWE reference(s): {', '.join(cwes)}")

    # Layer 2 — derived from knowledge graph traversal
    graph_context_signals: list[str] = []
    for cve_id, trace in cve_traces.items():
        has_capec = any(p.get("capec") for p in trace.get("paths", []))
        has_attack = any(p.get("attack") for p in trace.get("paths", []))
        if has_capec:
            capecs = list({p["capec"] for p in trace["paths"] if p.get("capec")})
            graph_context_signals.append(
                f"{cve_id} → CAPEC mapping(s): {', '.join(capecs)}"
            )
        if has_attack:
            attacks = list({p["attack"]["name"] for p in trace["paths"] if p.get("attack")})
            graph_context_signals.append(
                f"{cve_id} → possible ATT&CK technique(s): {', '.join(attacks)}"
            )

    # Layer 3 — prioritisation signals from scoring / patch data
    prioritization_signals: list[str] = []
    for cve_id, cve_data in cve_results.items():
        for entry in cve_data.get("cvss3", []):
            sev = (entry.get("severity") or "").upper()
            if sev in ("CRITICAL", "HIGH"):
                prioritization_signals.append(
                    f"{cve_id}: CVSS3 {sev} ({entry.get('score')})"
                )
        for ref in cve_data.get("references", []):
            url = (ref.get("url") or "").lower()
            name = (ref.get("name") or "").lower()
            if any(kw in url or kw in name for kw in ("patch", "advisory", "vendor")):
                prioritization_signals.append(
                    f"{cve_id}: patch/advisory reference available"
                )
                break

    warnings: list[str] = []
    limitations: list[str] = []

    for trace in cve_traces.values():
        warnings.extend(trace.get("warnings", []))

    if not cves and not cwes:
        limitations.append(
            "No CVE or CWE identifiers found in alert text. "
            "Consider Mode B (semantic search) for entity-free alerts."
        )
    if not product_vulns and not cves:
        limitations.append(
            "No product/CPE vulnerabilities retrieved. "
            "Provide product_hint for CPE-based lookup."
        )

    return {
        "observed_signals": observed_signals,
        "graph_context_signals": graph_context_signals,
        "prioritization_signals": prioritization_signals,
        "warnings": warnings,
        "limitations": limitations,
    }
