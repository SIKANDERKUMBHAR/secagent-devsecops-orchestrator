"""SARIF 2.1.0 report export."""

from __future__ import annotations

import json
from pathlib import Path

from secagent.core.models import UnifiedReport


def to_sarif(report: UnifiedReport) -> dict:
    rules = {}
    results = []
    for finding in report.findings:
        rule_id = finding.metadata.get("rule_id") or finding.id
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation or finding.description},
            }

        location = {}
        if finding.file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line_start or 1},
                }
            }
        results.append(
            {
                "ruleId": rule_id,
                "message": {"text": finding.description or finding.title},
                "level": _sarif_level(finding.severity.value),
                "locations": [location] if location else [],
                "properties": {
                    "tool": finding.tool,
                    "fingerprint": finding.fingerprint,
                    "status": finding.status.value,
                    "severity": finding.severity.value,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "secagent", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def write_sarif(report: UnifiedReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")


def _sarif_level(severity: str) -> str:
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"
