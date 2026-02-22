"""Core domain models for normalized findings and reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from secagent.constants import FindingStatus, Severity


class Finding(BaseModel):
    id: str
    fingerprint: str
    tool: str
    scanner_type: str
    category: str
    title: str
    description: str = ""
    severity: Severity = Severity.UNKNOWN
    confidence: str | None = None
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    resource: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str | None = None
    references: list[str] = Field(default_factory=list)
    remediation: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus = FindingStatus.ACTIVE
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScannerRun(BaseModel):
    scanner: str
    status: str
    duration_seconds: float = 0.0
    command: str = ""
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    return_code: int | None = None


class PolicyRuleResult(BaseModel):
    rule: str
    passed: bool
    message: str


class PolicyResult(BaseModel):
    passed: bool
    exit_code: int
    reasons: list[str] = Field(default_factory=list)
    violated_rules: list[PolicyRuleResult] = Field(default_factory=list)
    thresholds: dict[str, int] = Field(default_factory=dict)


class BaselineDiffSummary(BaseModel):
    baseline_path: str | None = None
    new_count: int = 0
    existing_count: int = 0


class SuppressionSummary(BaseModel):
    total_rules: int = 0
    applied_count: int = 0
    expired_count: int = 0
    invalid_count: int = 0


class ReportSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_scanner: dict[str, int]
    by_category: dict[str, int]


class ReportMetadata(BaseModel):
    schema_version: str
    generated_at: datetime
    target: str
    profile: str
    secagent_version: str
    git: dict[str, str] = Field(default_factory=dict)


class UnifiedReport(BaseModel):
    metadata: ReportMetadata
    scanner_runs: list[ScannerRun] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    summary: ReportSummary
    policy: PolicyResult
    baseline: BaselineDiffSummary
    suppressions: SuppressionSummary
    diagnostics: dict[str, Any] = Field(default_factory=dict)
