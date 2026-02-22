from datetime import date, timedelta
from pathlib import Path

import pytest

from secagent.config.models import PolicyConfig
from secagent.constants import FindingStatus, Severity
from secagent.core.baseline import apply_baseline
from secagent.core.dedupe import dedupe_findings
from secagent.core.models import Finding
from secagent.core.normalize import normalize_severity
from secagent.core.policy import evaluate_policy
from secagent.core.suppression import SuppressionError, SuppressionRule, apply_suppressions
from secagent.utils.masking import mask_secrets


def _finding(**kwargs) -> Finding:
    return Finding(
        id=kwargs.get("id", "f1"),
        fingerprint=kwargs.get("fingerprint", "fp1"),
        tool=kwargs.get("tool", "semgrep"),
        scanner_type=kwargs.get("scanner_type", "sast"),
        category=kwargs.get("category", "code"),
        title=kwargs.get("title", "Issue"),
        severity=kwargs.get("severity", Severity.HIGH),
        metadata=kwargs.get("metadata", {"rule_id": "R1"}),
        file_path=kwargs.get("file_path", "app.py"),
    )


def test_severity_normalization_unknown() -> None:
    assert normalize_severity("something") == Severity.UNKNOWN


def test_dedupe_returns_duplicates() -> None:
    f1 = _finding(id="1", fingerprint="abc")
    f2 = _finding(id="2", fingerprint="abc")
    unique, dupes = dedupe_findings([f1, f2])
    assert len(unique) == 1
    assert len(dupes) == 1


def test_policy_fail_on_high() -> None:
    findings = [_finding(severity=Severity.HIGH)]
    policy = PolicyConfig(fail_on_severities=["HIGH"], max_allowed={}, fail_on_secrets=False)
    result = evaluate_policy(findings, policy)
    assert result.passed is False


def test_policy_fail_new_only_excludes_baselined() -> None:
    finding = _finding(severity=Severity.HIGH)
    finding.status = FindingStatus.BASELINED
    policy = PolicyConfig(fail_on_severities=["HIGH"], fail_on_new_only=True, max_allowed={}, fail_on_secrets=False)
    result = evaluate_policy([finding], policy)
    assert result.passed is True


def test_apply_baseline_labels_findings() -> None:
    existing = _finding(fingerprint="old")
    new = _finding(id="n", fingerprint="new")
    diff = apply_baseline([existing, new], {"old"}, ".secagent-baseline.json")
    assert existing.status == FindingStatus.BASELINED
    assert new.status == FindingStatus.NEW
    assert diff.new_count == 1


def test_apply_suppressions_by_rule_and_path() -> None:
    finding = _finding(metadata={"rule_id": "CKV_DOCKER_2"}, file_path="examples/Dockerfile")
    rule = SuppressionRule(
        reason="example",
        expires=date.today() + timedelta(days=2),
        rule_id="CKV_DOCKER_2",
        path_glob="examples/**",
    )
    summary = apply_suppressions([finding], [rule])
    assert finding.status == FindingStatus.SUPPRESSED
    assert summary.applied_count == 1


def test_expired_suppression_raises() -> None:
    finding = _finding()
    rule = SuppressionRule(reason="x", expires=date.today() - timedelta(days=1), fingerprint=finding.fingerprint)
    with pytest.raises(SuppressionError):
        apply_suppressions([finding], [rule])


def test_masking_hides_token() -> None:
    text = "curl https://x token=abc123"
    assert "abc123" not in mask_secrets(text)
