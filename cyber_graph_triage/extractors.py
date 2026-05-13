from __future__ import annotations

import re


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)


def extract_cves(text: str) -> list[str]:
    return sorted({m.upper() for m in _CVE_RE.findall(text)})


def extract_cwes(text: str) -> list[str]:
    return sorted({m.upper() for m in _CWE_RE.findall(text)})


def extract_cpe_keywords(text: str, product_hint: str | None = None) -> list[str]:
    """Return CPE product keywords from an explicit hint or text heuristics."""
    if product_hint:
        return [product_hint.strip()]
    # Simple heuristic: look for vendor:product pairs (cpe-style)
    matches = re.findall(r"\b([a-z][a-z0-9_]+:[a-z][a-z0-9_]+)\b", text, re.IGNORECASE)
    return sorted({m.lower() for m in matches})
