"""Scanner plugin abstractions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from secagent.config.models import AppConfig
from secagent.core.models import Finding
from secagent.core.runner import CommandResult


@dataclass
class ScanContext:
    target: str
    output_dir: Path
    work_dir: Path
    config: AppConfig


class ScannerPlugin(ABC):
    name: str
    scanner_type: str
    category: str

    @abstractmethod
    def is_enabled(self, config: AppConfig) -> bool:
        """Return true if scanner should run."""

    @abstractmethod
    def build_command(self, context: ScanContext) -> list[str]:
        """Build scanner command."""

    @abstractmethod
    def parse(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse scanner output into intermediate findings."""

    @abstractmethod
    def normalize(self, parsed_findings: list[dict[str, Any]], include_raw: bool = False) -> list[Finding]:
        """Convert parsed findings into canonical finding objects."""

    def is_success_return_code(self, result: CommandResult) -> bool:
        """Tool-specific exit semantics override when needed."""
        return result.return_code == 0

    def timeout_seconds(self, config: AppConfig) -> int:
        """Tool-specific timeout lookup."""
        return 300
