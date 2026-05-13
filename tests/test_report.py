from cyber_graph_triage.report import format_triage_report


def _minimal_result(**overrides):
    base = {
        "mode": "SOC_TRIAGE",
        "input": {"alert_text": "test alert", "product_hint": None, "asset_hint": None},
        "extracted": {"cves": [], "cwes": [], "product_hint": None, "asset_hint": None},
        "results": {"cves": {}, "cve_traces": {}, "cwes": {}, "product_vulnerabilities": []},
        "assessment": {
            "observed_signals": [],
            "graph_context_signals": [],
            "prioritization_signals": [],
            "warnings": [],
            "limitations": [],
        },
        "evidence_paths": [],
    }
    base.update(overrides)
    return base


def test_report_formatter_handles_empty_result():
    result = _minimal_result()
    report = format_triage_report(result)
    assert "SOC Triage Report" in report
    assert "CVEs extracted: none" in report
    assert "CWEs extracted: none" in report
    assert "No evidence paths found." in report


def test_report_contains_limitations_disclaimer():
    result = _minimal_result()
    report = format_triage_report(result)
    assert "not assert that an attack was successful" in report


def test_report_with_cve_not_found():
    result = _minimal_result(
        extracted={"cves": ["CVE-2021-99999"], "cwes": [], "product_hint": None, "asset_hint": None},
        results={
            "cves": {"CVE-2021-99999": {"found": False, "cve": "CVE-2021-99999"}},
            "cve_traces": {},
            "cwes": {},
            "product_vulnerabilities": [],
        },
    )
    report = format_triage_report(result)
    assert "CVE-2021-99999" in report
    assert "Not found" in report


def test_triage_result_schema_minimal():
    result = _minimal_result()
    assert result["mode"] == "SOC_TRIAGE"
    assert "extracted" in result
    assert "results" in result
    assert "evidence_paths" in result
    assessment = result["assessment"]
    assert "observed_signals" in assessment
    assert "graph_context_signals" in assessment
    assert "prioritization_signals" in assessment
