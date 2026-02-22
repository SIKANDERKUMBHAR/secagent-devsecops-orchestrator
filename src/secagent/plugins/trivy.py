"""Trivy scanner plugin."""

from __future__ import annotations

import json
from typing import Any

from secagent.config.models import AppConfig
from secagent.constants import Severity
from secagent.core.fingerprint import generate_fingerprint
from secagent.core.models import Finding
from secagent.core.normalize import normalize_severity
from secagent.plugins.base import ScanContext, ScannerPlugin
from secagent.utils.masking import mask_secrets


class TrivyPlugin(ScannerPlugin):
    name = "trivy"
    scanner_type = "sca"
    category = "dependencies"

    def is_enabled(self, config: AppConfig) -> bool:
        return config.scanners.trivy

    def build_command(self, context: ScanContext) -> list[str]:
        command = ["trivy", context.config.trivy.scan_mode, "--format", "json", context.target]
        if context.config.trivy.severity:
            command.extend(["--severity", ",".join(context.config.trivy.severity)])
        if context.config.trivy.ignore_unfixed:
            command.append("--ignore-unfixed")
        return command

    def parse(self, raw_output: str) -> list[dict[str, Any]]:
        data = json.loads(raw_output or "{}")
        results = data.get("Results", [])
        flat: list[dict[str, Any]] = []
        for result in results:
            for vuln in result.get("Vulnerabilities", []) or []:
                merged = dict(vuln)
                merged["Target"] = result.get("Target")
                merged["__kind"] = "vulnerability"
                flat.append(merged)

            for misconf in result.get("Misconfigurations", []) or []:
                merged = dict(misconf)
                merged["Target"] = result.get("Target")
                merged["__kind"] = "misconfiguration"
                flat.append(merged)

            for secret in result.get("Secrets", []) or []:
                merged = dict(secret)
                merged["Target"] = result.get("Target")
                merged["__kind"] = "secret"
                flat.append(merged)
        return flat

    def normalize(self, parsed_findings: list[dict[str, Any]], include_raw: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for idx, item in enumerate(parsed_findings):
            refs = item.get("References", []) if isinstance(item.get("References", []), list) else []
            kind = item.get("__kind", "vulnerability")

            scanner_type = self.scanner_type
            category = self.category
            package_name = item.get("PkgName")
            installed_version = item.get("InstalledVersion")
            fixed_version = item.get("FixedVersion")
            cve_ids = [str(item.get("VulnerabilityID"))] if item.get("VulnerabilityID") else []
            evidence: dict[str, Any] = {}
            severity = normalize_severity(item.get("Severity"))

            if kind == "misconfiguration":
                scanner_type = "iac"
                category = "misconfiguration"
                package_name = None
                installed_version = None
                fixed_version = None
                cve_ids = []

            if kind == "secret":
                scanner_type = "secrets"
                category = "secrets"
                package_name = None
                installed_version = None
                fixed_version = None
                cve_ids = []
                severity = normalize_severity(item.get("Severity"))
                if severity == Severity.UNKNOWN:
                    severity = Severity.HIGH
                evidence = {
                    "match": mask_secrets(str(item.get("Match", ""))),
                    "secret": "***",
                }

            finding = Finding(
                id=f"trivy-{idx}",
                fingerprint="",
                tool=self.name,
                scanner_type=scanner_type,
                category=category,
                title=item.get("Title") or item.get("VulnerabilityID") or item.get("ID", "Trivy finding"),
                description=item.get("Description", ""),
                severity=severity,
                package_name=package_name,
                installed_version=installed_version,
                fixed_version=fixed_version,
                cve_ids=cve_ids,
                cvss_score=(item.get("CVSS", {}).get("nvd", {}) or {}).get("V3Score"),
                references=[r for r in refs if isinstance(r, str)],
                resource=item.get("Target"),
                remediation="Upgrade to fixed version where available.",
                evidence=evidence,
                raw=item if include_raw else None,
                metadata={"rule_id": item.get("VulnerabilityID") or item.get("ID", "")},
            )
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)
        return findings

    def timeout_seconds(self, config: AppConfig) -> int:
        return config.trivy.timeout_seconds

    def is_success_return_code(self, result) -> bool:
        return result.return_code in (0, 1)
