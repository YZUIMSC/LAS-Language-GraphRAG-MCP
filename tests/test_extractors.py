from cyber_graph_triage.extractors import extract_cves, extract_cwes, extract_cpe_keywords


def test_extract_cves_basic():
    text = "Alert: CVE-2021-34709 and cve-2020-1234 on the same host."
    result = extract_cves(text)
    assert "CVE-2021-34709" in result
    assert "CVE-2020-1234" in result
    assert all(c == c.upper() for c in result)


def test_extract_cves_none():
    assert extract_cves("No vulnerabilities mentioned here.") == []


def test_extract_cwes_basic():
    text = "This involves CWE-79 and cwe-692 injection flaws."
    result = extract_cwes(text)
    assert "CWE-79" in result
    assert "CWE-692" in result
    assert all(c == c.upper() for c in result)


def test_extract_cwes_none():
    assert extract_cwes("Nothing here.") == []


def test_extract_cpe_keywords_with_hint():
    result = extract_cpe_keywords("some alert text", product_hint="apache:struts")
    assert result == ["apache:struts"]


def test_extract_cpe_keywords_no_hint():
    text = "Vulnerability in cisco:ios version found"
    result = extract_cpe_keywords(text)
    assert "cisco:ios" in result


def test_extract_cves_dedup():
    text = "CVE-2021-34709 triggered again CVE-2021-34709"
    result = extract_cves(text)
    assert result.count("CVE-2021-34709") == 1
