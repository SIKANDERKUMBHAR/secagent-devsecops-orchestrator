"""Normalization helpers for severities and report ordering."""

from __future__ import annotations

from collections import Counter

from secagent.constants import Severity
from secagent.core.models import Finding, ReportSummary

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}

_GENERIC_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "error": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


def normalize_severity(raw: str | None) -> Severity:
    if not raw:
        return Severity.UNKNOWN
    return _GENERIC_MAP.get(raw.strip().lower(), Severity.UNKNOWN)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            f.title.lower(),
            f.tool,
            f.fingerprint,
        ),
    )


def build_summary(findings: list[Finding]) -> ReportSummary:
    by_sev = Counter(f.severity.value for f in findings)
    by_scanner = Counter(f.tool for f in findings)
    by_category = Counter(f.category for f in findings)
    return ReportSummary(
        total=len(findings),
        by_severity=dict(by_sev),
        by_scanner=dict(by_scanner),
        by_category=dict(by_category),
    )
