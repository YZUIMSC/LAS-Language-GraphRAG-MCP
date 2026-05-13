from __future__ import annotations

from typing import Any


def format_triage_report(result: dict[str, Any]) -> str:
    lines: list[str] = []
    _h1(lines, "SOC Triage Report — Mode A")

    extracted = result.get("extracted", {})
    results = result.get("results", {})
    assessment = result.get("assessment", {})
    evidence_paths = result.get("evidence_paths", [])
    alert_text = result.get("input", {}).get("alert_text", "")

    # Summary
    _h2(lines, "Summary")
    cves = extracted.get("cves", [])
    cwes = extracted.get("cwes", [])
    lines.append(f"- Alert text: `{alert_text[:200]}`")
    lines.append(f"- CVEs extracted: {', '.join(cves) if cves else 'none'}")
    lines.append(f"- CWEs extracted: {', '.join(cwes) if cwes else 'none'}")
    product_hint = extracted.get("product_hint")
    if product_hint:
        lines.append(f"- Product hint: `{product_hint}`")
    asset_hint = extracted.get("asset_hint")
    if asset_hint:
        lines.append(f"- Asset hint: `{asset_hint}`")
    else:
        lines.append("- Asset: not confirmed (CPE-based lookup only if product_hint provided)")
    lines.append("")

    # Extracted Entities
    _h2(lines, "Extracted Entities")
    lines.append(f"**CVEs:** {', '.join(cves) if cves else 'none'}")
    lines.append(f"**CWEs:** {', '.join(cwes) if cwes else 'none'}")
    lines.append("")

    # CVE Findings
    _h2(lines, "CVE Findings")
    cve_results = results.get("cves", {})
    if not cve_results:
        lines.append("No CVEs queried.")
    for cve_id, data in cve_results.items():
        _h3(lines, cve_id)
        if not data.get("found"):
            lines.append(f"- Not found in graph. Error: {data.get('error', 'N/A')}")
            continue
        lines.append(f"- **Description:** {data.get('description') or 'N/A'}")
        lines.append(f"- **Published:** {data.get('published_date') or 'N/A'}")
        for entry in data.get("cvss3", []):
            lines.append(
                f"- **CVSS3:** {entry.get('score')} ({entry.get('severity')}) — `{entry.get('vector')}`"
            )
        lines.append(f"- **Related CWEs:** {', '.join(data.get('cwes', [])) or 'none'}")
        cpes = data.get("cpes", [])
        if cpes:
            lines.append(f"- **Affected CPEs ({len(cpes)}):** {', '.join(cpes[:5])}" + (" ..." if len(cpes) > 5 else ""))
        refs = data.get("references", [])
        if refs:
            lines.append(f"- **References ({len(refs)}):**")
            for ref in refs[:5]:
                url = ref.get("url") or ref.get("name") or ""
                lines.append(f"  - {url}")
        lines.append("")

    # CWE Context
    _h2(lines, "CWE / Weakness Context")
    cwe_results = results.get("cwes", {})
    if not cwe_results:
        lines.append("No CWEs queried.")
    for cwe_id, data in cwe_results.items():
        _h3(lines, cwe_id)
        if not data.get("found"):
            lines.append(f"- Not found in graph. Error: {data.get('error', 'N/A')}")
            continue
        lines.append(f"- **Name:** {data.get('name') or 'N/A'}")
        lines.append(f"- **Description:** {data.get('description') or 'N/A'}")
        lines.append(f"- **Abstraction:** {data.get('abstraction') or 'N/A'}")
        related = data.get("related_cwes", [])
        if related:
            lines.append(f"- **Related Weaknesses ({len(related)}):**")
            for r in related[:5]:
                lines.append(f"  - [{r.get('nature')}] {r.get('target')} — {r.get('target_name') or ''}")
        mitigations = data.get("mitigations", [])
        if mitigations:
            lines.append(f"- **Mitigations ({len(mitigations)}):**")
            for m in mitigations[:3]:
                lines.append(f"  - {m[:200]}")
        lines.append("")

    # Evidence Paths
    _h2(lines, "Evidence Paths (CVE → CWE → CAPEC → ATT&CK)")
    if not evidence_paths:
        lines.append("No evidence paths found.")
    for path in evidence_paths:
        parts = [f"CVE: {path.get('cve')}"]
        if path.get("cwe"):
            parts.append(f"CWE: {path.get('cwe')} ({path.get('cwe_name') or ''})")
        if path.get("capec"):
            parts.append(f"CAPEC: {path.get('capec')} ({path.get('capec_name') or ''})")
        attack = path.get("attack")
        if attack:
            parts.append(
                f"ATT&CK: {attack.get('id')} — {attack.get('name')} "
                f"[via {attack.get('relation')}] *(possible mapping, not observed technique)*"
            )
        else:
            parts.append("ATT&CK: not mapped")
        lines.append("- " + " → ".join(parts))
    lines.append("")

    # Risk Signals
    _h2(lines, "Risk Signals")
    risk_signals = assessment.get("risk_signals", [])
    if risk_signals:
        for sig in risk_signals:
            lines.append(f"- {sig}")
    else:
        lines.append("No high-confidence risk signals identified from graph data.")
    lines.append("")

    # Limitations
    _h2(lines, "Limitations")
    limitations = assessment.get("limitations", [])
    warnings = assessment.get("warnings", [])
    all_notes = limitations + warnings
    if all_notes:
        for note in all_notes:
            lines.append(f"- {note}")
    else:
        lines.append("No limitations noted.")
    lines.append("- CAPEC/ATT&CK mappings indicate possible attack patterns, not confirmed observed techniques.")
    lines.append("- This report does not assert that an attack was successful.")
    lines.append("")

    # Recommended Next Actions
    _h2(lines, "Recommended Next Actions")
    lines.append("- Validate whether affected CPEs match assets in your environment.")
    if any(data.get("found") for data in cve_results.values()):
        lines.append("- Apply available patches or mitigations referenced above.")
    lines.append("- Cross-reference with SIEM/EDR telemetry for observed indicators.")
    if not cves and not cwes:
        lines.append("- Run Mode B (semantic search) to find related vulnerabilities without explicit CVE/CWE IDs.")
    lines.append("")

    return "\n".join(lines)


def _h1(lines: list, text: str) -> None:
    lines.extend([f"# {text}", ""])


def _h2(lines: list, text: str) -> None:
    lines.extend([f"## {text}", ""])


def _h3(lines: list, text: str) -> None:
    lines.extend([f"### {text}", ""])
