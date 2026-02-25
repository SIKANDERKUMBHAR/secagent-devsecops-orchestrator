"""CSV report generation."""

from __future__ import annotations

import csv
from pathlib import Path

from secagent.core.models import UnifiedReport


def write_csv(report: UnifiedReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_fields())
        writer.writeheader()
        for finding in report.findings:
            writer.writerow(
                {
                    "id": finding.id,
                    "fingerprint": finding.fingerprint,
                    "tool": finding.tool,
                    "scanner_type": finding.scanner_type,
                    "category": finding.category,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "status": finding.status.value,
                    "file_path": finding.file_path or "",
                    "line_start": finding.line_start or "",
                    "resource": finding.resource or "",
                    "rule_id": finding.metadata.get("rule_id", ""),
                    "package_name": finding.package_name or "",
                    "installed_version": finding.installed_version or "",
                    "fixed_version": finding.fixed_version or "",
                    "cve_ids": ";".join(finding.cve_ids),
                    "cwe_ids": ";".join(finding.cwe_ids),
                    "owasp_categories": ";".join(finding.owasp_categories),
                    "cvss_score": finding.cvss_score or "",
                    "references": ";".join(finding.references),
                    "remediation": finding.remediation,
                }
            )


def _fields() -> list[str]:
    return [
        "id",
        "fingerprint",
        "tool",
        "scanner_type",
        "category",
        "title",
        "description",
        "severity",
        "status",
        "file_path",
        "line_start",
        "resource",
        "rule_id",
        "package_name",
        "installed_version",
        "fixed_version",
        "cve_ids",
        "cwe_ids",
        "owasp_categories",
        "cvss_score",
        "references",
        "remediation",
    ]
