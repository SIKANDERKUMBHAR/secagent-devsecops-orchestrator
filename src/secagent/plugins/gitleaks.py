"""Gitleaks scanner plugin."""

from __future__ import annotations

import json
from typing import Any

from secagent.config.models import AppConfig
from secagent.core.fingerprint import generate_fingerprint
from secagent.core.models import Finding
from secagent.constants import Severity
from secagent.plugins.base import ScanContext, ScannerPlugin
from secagent.utils.masking import mask_secrets


class GitleaksPlugin(ScannerPlugin):
    name = "gitleaks"
    scanner_type = "secrets"
    category = "secrets"

    def is_enabled(self, config: AppConfig) -> bool:
        return config.scanners.gitleaks

    def build_command(self, context: ScanContext) -> list[str]:
        output = str(context.work_dir / "gitleaks.json")
        command = ["gitleaks", "detect", "--source", context.target, "--report-format", "json", "--report-path", output]
        if context.config.gitleaks.redact:
            command.append("--redact")
        return command

    def parse(self, raw_output: str) -> list[dict[str, Any]]:
        if not raw_output.strip():
            return []
        return json.loads(raw_output)

    def normalize(self, parsed_findings: list[dict[str, Any]], include_raw: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for idx, item in enumerate(parsed_findings):
            finding = Finding(
                id=f"gitleaks-{idx}",
                fingerprint="",
                tool=self.name,
                scanner_type=self.scanner_type,
                category=self.category,
                title=item.get("Description", "Leaked secret"),
                description="Potential secret detected",
                severity=Severity.HIGH,
                file_path=item.get("File"),
                line_start=item.get("StartLine"),
                line_end=item.get("EndLine"),
                evidence={
                    "match": mask_secrets(str(item.get("Match", ""))),
                    "secret": "***",
                },
                remediation="Rotate the secret and remove it from source control history.",
                raw=item if include_raw else None,
                metadata={"rule_id": item.get("RuleID", "")},
            )
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)
        return findings

    def is_success_return_code(self, result) -> bool:
        return result.return_code in (0, 1)

    def timeout_seconds(self, config: AppConfig) -> int:
        return config.gitleaks.timeout_seconds
