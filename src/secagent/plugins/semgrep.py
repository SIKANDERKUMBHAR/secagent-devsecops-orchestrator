"""Semgrep scanner plugin."""

from __future__ import annotations

import json
from typing import Any

from secagent.config.models import AppConfig
from secagent.core.fingerprint import generate_fingerprint
from secagent.core.models import Finding
from secagent.core.normalize import normalize_severity
from secagent.plugins.base import ScanContext, ScannerPlugin


class SemgrepPlugin(ScannerPlugin):
    name = "semgrep"
    scanner_type = "sast"
    category = "code"

    def is_enabled(self, config: AppConfig) -> bool:
        return config.scanners.semgrep

    def build_command(self, context: ScanContext) -> list[str]:
        return ["semgrep", "--json", "--config", context.config.semgrep.config, context.target]

    def parse(self, raw_output: str) -> list[dict[str, Any]]:
        data = json.loads(raw_output or "{}")
        return data.get("results", [])

    def normalize(self, parsed_findings: list[dict[str, Any]], include_raw: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for idx, item in enumerate(parsed_findings):
            extra = item.get("extra", {})
            metadata = extra.get("metadata", {})
            finding = Finding(
                id=f"semgrep-{idx}",
                fingerprint="",
                tool=self.name,
                scanner_type=self.scanner_type,
                category=self.category,
                title=extra.get("message", item.get("check_id", "Semgrep finding")),
                description=extra.get("message", ""),
                severity=normalize_severity(extra.get("severity")),
                file_path=item.get("path"),
                line_start=item.get("start", {}).get("line"),
                line_end=item.get("end", {}).get("line"),
                references=[r for r in metadata.get("references", []) if isinstance(r, str)],
                cwe_ids=metadata.get("cwe", []) if isinstance(metadata.get("cwe", []), list) else [],
                owasp_categories=metadata.get("owasp", []) if isinstance(metadata.get("owasp", []), list) else [],
                remediation=metadata.get("remediation", ""),
                raw=item if include_raw else None,
                metadata={"rule_id": item.get("check_id", "")},
            )
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)
        return findings

    def is_success_return_code(self, result) -> bool:
        return result.return_code in (0, 1)

    def timeout_seconds(self, config: AppConfig) -> int:
        return config.semgrep.timeout_seconds
