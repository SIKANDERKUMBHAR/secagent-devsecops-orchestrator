"""Baseline create/load/compare helpers."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from secagent.constants import FindingStatus, SCHEMA_VERSION_BASELINE
from secagent.core.models import BaselineDiffSummary, Finding


def create_baseline_file(path: Path, findings: list[Finding], target: str) -> None:
    payload = {
        "schema_version": SCHEMA_VERSION_BASELINE,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "entries": [
            {
                "fingerprint": f.fingerprint,
                "title": f.title,
                "severity": f.severity.value,
                "tool": f.tool,
            }
            for f in findings
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    data = json.loads(path.read_text(encoding="utf-8"))
    return {entry["fingerprint"] for entry in data.get("entries", []) if "fingerprint" in entry}


def apply_baseline(findings: list[Finding], baseline_fingerprints: set[str], baseline_path: str | None = None) -> BaselineDiffSummary:
    new_count = 0
    existing_count = 0
    for finding in findings:
        if finding.fingerprint in baseline_fingerprints:
            finding.status = FindingStatus.BASELINED
            existing_count += 1
        else:
            finding.status = FindingStatus.NEW
            new_count += 1
    return BaselineDiffSummary(baseline_path=baseline_path, new_count=new_count, existing_count=existing_count)
