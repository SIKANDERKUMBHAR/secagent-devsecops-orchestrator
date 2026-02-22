"""Policy evaluation engine."""

from __future__ import annotations

from collections import Counter

from secagent.config.models import PolicyConfig
from secagent.constants import ExitCode, FindingStatus
from secagent.core.models import Finding, PolicyResult, PolicyRuleResult


def evaluate_policy(findings: list[Finding], policy: PolicyConfig) -> PolicyResult:
    considered = [f for f in findings if f.status != FindingStatus.SUPPRESSED]
    if policy.fail_on_new_only:
        considered = [f for f in considered if f.status == FindingStatus.NEW]

    violations: list[PolicyRuleResult] = []
    sev_counts = Counter(f.severity.value for f in considered)

    fail_sev = set(policy.fail_on_severities)
    severities_present = [sev for sev in fail_sev if sev_counts.get(sev, 0) > 0]
    if severities_present:
        violations.append(
            PolicyRuleResult(
                rule="fail_on_severities",
                passed=False,
                message=f"Disallowed severities present: {', '.join(sorted(severities_present))}",
            )
        )

    for sev, limit in policy.max_allowed.items():
        actual = sev_counts.get(sev, 0)
        if actual > limit:
            violations.append(
                PolicyRuleResult(
                    rule="max_allowed",
                    passed=False,
                    message=f"{sev} count {actual} exceeds limit {limit}",
                )
            )

    if policy.fail_on_secrets and any(f.scanner_type == "secrets" for f in considered):
        violations.append(
            PolicyRuleResult(
                rule="fail_on_secrets",
                passed=False,
                message="Secret findings present",
            )
        )

    passed = len(violations) == 0
    return PolicyResult(
        passed=passed,
        exit_code=ExitCode.SUCCESS if passed else ExitCode.POLICY_FAILED,
        reasons=[v.message for v in violations],
        violated_rules=violations,
        thresholds=dict(sev_counts),
    )
