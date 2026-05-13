from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CveResult(BaseModel):
    found: bool
    cve: str
    description: str | None = None
    published_date: str | None = None
    last_modified_date: str | None = None
    cwes: list[str] = Field(default_factory=list)
    cvss3: list[dict[str, Any]] = Field(default_factory=list)
    cvss2: list[dict[str, Any]] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    references: list[dict[str, Any]] = Field(default_factory=list)


class CweResult(BaseModel):
    found: bool
    cwe: str
    name: str | None = None
    description: str | None = None
    abstraction: str | None = None
    structure: str | None = None
    status: str | None = None
    related_cwes: list[dict[str, Any]] = Field(default_factory=list)
    capecs: list[dict[str, Any]] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    consequences: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    cwe: str | None = None
    cwe_name: str | None = None
    capec: str | None = None
    capec_name: str | None = None
    attack: dict[str, str] | None = None


class TraceResult(BaseModel):
    found: bool
    cve: str
    paths: list[AttackPath] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CpeVulnRow(BaseModel):
    cve: str
    cpe: str | None = None
    vulnerable: bool | None = None
    score: float | None = None
    severity: str | None = None
    cwes: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    mode: str = "SOC_TRIAGE"
    input: dict[str, Any] = Field(default_factory=dict)
    extracted: dict[str, Any] = Field(default_factory=dict)
    results: dict[str, Any] = Field(default_factory=dict)
    assessment: dict[str, Any] = Field(default_factory=dict)
    evidence_paths: list[dict[str, Any]] = Field(default_factory=list)
    report: str | None = None
