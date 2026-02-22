from datetime import datetime, timezone
from pathlib import Path

from secagent.constants import FindingStatus, Severity
from secagent.core.models import (
    BaselineDiffSummary,
    Finding,
    PolicyResult,
    ReportMetadata,
    ReportSummary,
    SuppressionSummary,
    UnifiedReport,
)
from secagent.reports.html_report import render_html_report
from secagent.reports.markdown_report import write_markdown
from secagent.reports.sarif_report import to_sarif


def _report() -> UnifiedReport:
    finding = Finding(
        id="f1",
        fingerprint="abc",
        tool="semgrep",
        scanner_type="sast",
        category="code",
        title="Issue",
        description="desc",
        severity=Severity.HIGH,
        file_path="app.py",
        line_start=2,
        status=FindingStatus.NEW,
        metadata={"rule_id": "R1"},
    )
    return UnifiedReport(
        metadata=ReportMetadata(
            schema_version="1.0.0",
            generated_at=datetime.now(timezone.utc),
            target=".",
            profile="ci",
            secagent_version="0.1.0",
        ),
        findings=[finding],
        scanner_runs=[],
        summary=ReportSummary(total=1, by_severity={"HIGH": 1}, by_scanner={"semgrep": 1}, by_category={"code": 1}),
        policy=PolicyResult(passed=False, exit_code=1, reasons=["x"], violated_rules=[]),
        baseline=BaselineDiffSummary(new_count=1, existing_count=0),
        suppressions=SuppressionSummary(),
    )


def test_html_render_smoke(tmp_path: Path) -> None:
    output = tmp_path / "report.html"
    render_html_report(_report(), output)
    content = output.read_text(encoding="utf-8")
    assert "SecAgent Security Report" in content
    assert "Issue" in content


def test_sarif_shape() -> None:
    sarif = to_sarif(_report())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "R1"


def test_markdown_report_smoke(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    write_markdown(_report(), output)
    content = output.read_text(encoding="utf-8")
    assert "# SecAgent Security Report" in content
    assert "Issue" in content
