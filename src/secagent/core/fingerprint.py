"""Deterministic fingerprint generation for findings."""

from __future__ import annotations

import hashlib

from secagent.core.models import Finding


def generate_fingerprint_parts(finding: Finding) -> list[str]:
    return [
        finding.scanner_type,
        finding.category,
        finding.title,
        finding.file_path or "",
        str(finding.line_start or ""),
        finding.resource or "",
        finding.package_name or "",
        finding.installed_version or "",
        ",".join(sorted(finding.cve_ids)),
        ",".join(sorted(finding.cwe_ids)),
        finding.metadata.get("rule_id", ""),
    ]


def generate_fingerprint(finding: Finding) -> str:
    joined = "|".join(generate_fingerprint_parts(finding))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()
