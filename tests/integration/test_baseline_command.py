import json
from pathlib import Path

from typer.testing import CliRunner

from secagent.cli import app

runner = CliRunner()


def test_baseline_create_from_report(tmp_path: Path) -> None:
    report = {
        "metadata": {
            "schema_version": "1.0.0",
            "generated_at": "2026-01-01T00:00:00Z",
            "target": ".",
            "profile": "ci",
            "secagent_version": "0.1.0",
            "git": {},
        },
        "scanner_runs": [],
        "findings": [
            {
                "id": "1",
                "fingerprint": "fp1",
                "tool": "semgrep",
                "scanner_type": "sast",
                "category": "code",
                "title": "Issue",
                "description": "",
                "severity": "LOW",
                "cve_ids": [],
                "cwe_ids": [],
                "owasp_categories": [],
                "references": [],
                "remediation": "",
                "evidence": {},
                "status": "new",
                "metadata": {},
            }
        ],
        "summary": {"total": 1, "by_severity": {"LOW": 1}, "by_scanner": {"semgrep": 1}, "by_category": {"code": 1}},
        "policy": {"passed": True, "exit_code": 0, "reasons": [], "violated_rules": [], "thresholds": {}},
        "baseline": {"baseline_path": None, "new_count": 1, "existing_count": 0},
        "suppressions": {"total_rules": 0, "applied_count": 0, "expired_count": 0, "invalid_count": 0},
        "diagnostics": {},
    }
    report_path = tmp_path / "report.json"
    baseline_path = tmp_path / "baseline.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = runner.invoke(app, ["baseline", "create", "--input-json", str(report_path), "--output", str(baseline_path)])
    assert result.exit_code == 0
    payload = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert payload["entries"][0]["fingerprint"] == "fp1"
