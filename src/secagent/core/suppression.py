"""Suppression file parsing and finding matching."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path
from fnmatch import fnmatch

import yaml

from secagent.constants import FindingStatus
from secagent.core.models import Finding, SuppressionSummary


@dataclass
class SuppressionRule:
    reason: str
    expires: date
    fingerprint: str | None = None
    rule_id: str | None = None
    path_glob: str | None = None
    tools: list[str] | None = None


class SuppressionError(ValueError):
    """Raised when suppression file is invalid."""


def load_suppressions(path: Path | None) -> list[SuppressionRule]:
    if path is None or not path.exists():
        return []

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rules = data.get("suppressions", [])
    parsed: list[SuppressionRule] = []

    for idx, raw in enumerate(rules):
        reason = raw.get("reason")
        expires_raw = raw.get("expires")
        if not reason or not expires_raw:
            raise SuppressionError(f"Suppression at index {idx} must include reason and expires")
        parsed.append(
            SuppressionRule(
                reason=reason,
                expires=date.fromisoformat(str(expires_raw)),
                fingerprint=raw.get("fingerprint"),
                rule_id=raw.get("rule_id"),
                path_glob=raw.get("path_glob"),
                tools=raw.get("tools"),
            )
        )
    return parsed


def apply_suppressions(
    findings: list[Finding],
    rules: list[SuppressionRule],
    reject_expired: bool = True,
) -> SuppressionSummary:
    today = date.today()
    summary = SuppressionSummary(total_rules=len(rules))
    for rule in rules:
        if rule.expires < today:
            summary.expired_count += 1
            if reject_expired:
                raise SuppressionError(f"Suppression expired: {rule.reason}")
            continue

        for finding in findings:
            if _matches(finding, rule):
                finding.status = FindingStatus.SUPPRESSED
                finding.metadata["suppression_reason"] = rule.reason
                finding.metadata["suppression_expires"] = rule.expires.isoformat()
                summary.applied_count += 1
    return summary


def _matches(finding: Finding, rule: SuppressionRule) -> bool:
    if rule.fingerprint and finding.fingerprint != rule.fingerprint:
        return False
    if rule.tools and finding.tool not in rule.tools:
        return False
    if rule.rule_id and finding.metadata.get("rule_id") != rule.rule_id:
        return False
    if rule.path_glob and finding.file_path:
        return fnmatch(finding.file_path, rule.path_glob)
    return any([rule.fingerprint, rule.rule_id])
