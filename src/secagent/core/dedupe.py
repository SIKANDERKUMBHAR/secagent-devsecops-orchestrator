"""Conservative deduplication for normalized findings."""

from __future__ import annotations

from secagent.core.models import Finding


def dedupe_findings(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    seen: dict[str, Finding] = {}
    duplicates: list[Finding] = []
    unique: list[Finding] = []

    for finding in findings:
        if finding.fingerprint in seen:
            duplicates.append(finding)
            continue
        seen[finding.fingerprint] = finding
        unique.append(finding)

    return unique, duplicates
