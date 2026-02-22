"""Markdown report generation."""

from __future__ import annotations

from pathlib import Path

from secagent.core.models import UnifiedReport


def write_markdown(report: UnifiedReport, output_path: Path) -> None:
    lines: list[str] = []
    lines.append("# SecAgent Security Report")
    lines.append("")
    lines.append(f"- Generated: {report.metadata.generated_at}")
    lines.append(f"- Target: `{report.metadata.target}`")
    lines.append(f"- Profile: `{report.metadata.profile}`")
    lines.append(f"- Policy: **{'PASS' if report.policy.passed else 'FAIL'}**")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total findings: **{report.summary.total}**")
    for sev, count in sorted(report.summary.by_severity.items()):
        lines.append(f"- {sev}: {count}")
    lines.append("")
    lines.append("## Scanner Runs")
    lines.append("")
    lines.append("| Scanner | Status | Duration (s) | Return Code |")
    lines.append("|---|---|---:|---:|")
    for run in report.scanner_runs:
        code = "" if run.return_code is None else str(run.return_code)
        lines.append(f"| {run.scanner} | {run.status} | {run.duration_seconds:.2f} | {code} |")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append("No findings detected.")
    else:
        lines.append("| Severity | Title | Tool | Location | Status | Fingerprint |")
        lines.append("|---|---|---|---|---|---|")
        for finding in report.findings:
            location = finding.file_path or finding.resource or "-"
            if finding.line_start:
                location = f"{location}:{finding.line_start}"
            lines.append(
                "| "
                f"{finding.severity.value} | "
                f"{_sanitize_pipe(finding.title)} | "
                f"{finding.tool} | "
                f"{_sanitize_pipe(location)} | "
                f"{finding.status.value} | "
                f"`{finding.fingerprint}` |"
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sanitize_pipe(value: str) -> str:
    return value.replace("|", "\\|")
