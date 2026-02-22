"""Checkov scanner plugin."""

from __future__ import annotations

import json
from typing import Any

from secagent.config.models import AppConfig
from secagent.core.fingerprint import generate_fingerprint
from secagent.core.models import Finding
from secagent.core.normalize import normalize_severity
from secagent.plugins.base import ScanContext, ScannerPlugin


class CheckovPlugin(ScannerPlugin):
    name = "checkov"
    scanner_type = "iac"
    category = "misconfiguration"

    def is_enabled(self, config: AppConfig) -> bool:
        return config.scanners.checkov

    def build_command(self, context: ScanContext) -> list[str]:
        command = ["checkov", "-d", context.target, "-o", "json"]
        if context.config.checkov.framework:
            command.extend(["--framework", ",".join(context.config.checkov.framework)])
        return command

    def parse(self, raw_output: str) -> list[dict[str, Any]]:
        data = json.loads(raw_output or "{}")
        results = data.get("results", {})
        return results.get("failed_checks", [])

    def normalize(self, parsed_findings: list[dict[str, Any]], include_raw: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for idx, item in enumerate(parsed_findings):
            guideline = item.get("guideline", "")
            finding = Finding(
                id=f"checkov-{idx}",
                fingerprint="",
                tool=self.name,
                scanner_type=self.scanner_type,
                category=self.category,
                title=item.get("check_name", item.get("check_id", "Checkov finding")),
                description=item.get("description") or "",
                severity=normalize_severity(item.get("severity")),
                file_path=item.get("file_path"),
                line_start=(item.get("file_line_range") or [None])[0],
                line_end=(item.get("file_line_range") or [None, None])[-1],
                resource=item.get("resource"),
                references=[guideline] if guideline else [],
                remediation=guideline,
                raw=item if include_raw else None,
                metadata={"rule_id": item.get("check_id", "")},
            )
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)
        return findings

    def is_success_return_code(self, result) -> bool:
        return result.return_code in (0, 1)

    def timeout_seconds(self, config: AppConfig) -> int:
        return config.checkov.timeout_seconds
