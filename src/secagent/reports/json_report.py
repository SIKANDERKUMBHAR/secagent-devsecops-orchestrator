"""JSON report writer."""

from __future__ import annotations

import json
from pathlib import Path

from secagent.core.models import UnifiedReport


def write_json(report: UnifiedReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
