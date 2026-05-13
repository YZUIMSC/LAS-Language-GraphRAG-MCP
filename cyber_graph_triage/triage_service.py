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
        product_vulns.extend(lookup_cpe_vulnerabilities(client, kw))

    evidence_paths = _collect_evidence_paths(cve_traces)
    risk_signals, warnings, limitations = _assess(
        cve_results, cwe_results, cve_traces, product_vulns, cves, cwes
    )

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
        "assessment": {
            "risk_signals": risk_signals,
            "warnings": warnings,
            "limitations": limitations,
        },
        "evidence_paths": evidence_paths,
    }

    if include_report:
        result["report"] = format_triage_report(result)

    return result


def _collect_evidence_paths(cve_traces: dict[str, Any]) -> list[dict[str, Any]]:
    paths = []
    for cve_id, trace in cve_traces.items():
        for p in trace.get("paths", []):
            if p.get("cwe") or p.get("capec"):
                paths.append({"cve": cve_id, **p})
    return paths


def _assess(
    cve_results: dict,
    cwe_results: dict,
    cve_traces: dict,
    product_vulns: list,
    cves: list,
    cwes: list,
) -> tuple[list[str], list[str], list[str]]:
    risk_signals: list[str] = []
    warnings: list[str] = []
    limitations: list[str] = []

    for cve_id, cve_data in cve_results.items():
        for score_entry in cve_data.get("cvss3", []):
            sev = (score_entry.get("severity") or "").upper()
            if sev in ("CRITICAL", "HIGH"):
                risk_signals.append(f"{cve_id}: CVSS3 severity {sev} ({score_entry.get('score')})")

        for ref in cve_data.get("references", []):
            url = (ref.get("url") or "").lower()
            name = (ref.get("name") or "").lower()
            if any(kw in url or kw in name for kw in ("patch", "advisory", "vendor")):
                risk_signals.append(f"{cve_id}: patch/advisory reference available")
                break

    for cve_id, trace in cve_traces.items():
        has_capec = any(p.get("capec") for p in trace.get("paths", []))
        has_attack = any(p.get("attack") for p in trace.get("paths", []))
        if has_capec:
            risk_signals.append(f"{cve_id}: mapped to CAPEC attack pattern(s)")
        if has_attack:
            risk_signals.append(f"{cve_id}: potential ATT&CK technique mapping found")
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

    return risk_signals, warnings, limitations
