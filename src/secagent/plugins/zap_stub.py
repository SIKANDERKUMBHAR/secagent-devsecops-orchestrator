"""ZAP plugin stub for v1 architecture completeness."""

from __future__ import annotations

from secagent.config.models import AppConfig
from secagent.core.models import Finding
from secagent.plugins.base import ScanContext, ScannerPlugin


class ZapStubPlugin(ScannerPlugin):
    name = "zap"
    scanner_type = "dast"
    category = "runtime"

    def is_enabled(self, config: AppConfig) -> bool:
        return config.scanners.zap and config.zap.enabled

    def build_command(self, context: ScanContext) -> list[str]:
        return ["echo", "ZAP stub plugin"]

    def parse(self, raw_output: str) -> list[dict]:
        return []

    def normalize(self, parsed_findings: list[dict], include_raw: bool = False) -> list[Finding]:
        return []

    def timeout_seconds(self, config: AppConfig) -> int:
        return config.zap.timeout_seconds
