from pathlib import Path

from typer.testing import CliRunner

from secagent.cli import app
from secagent.core.runner import CommandResult

runner = CliRunner()


def test_scan_generates_reports_with_mocked_plugin(monkeypatch, tmp_path: Path) -> None:
    from secagent.plugins.base import ScannerPlugin
    from secagent.core.models import Finding
    from secagent.constants import Severity

    class FakePlugin(ScannerPlugin):
        name = "fake"
        scanner_type = "sast"
        category = "code"

        def is_enabled(self, config):
            return True

        def build_command(self, context):
            return ["fake", "scan"]

        def parse(self, raw_output):
            return [{"x": 1}]

        def normalize(self, parsed_findings, include_raw=False):
            return [
                Finding(
                    id="f1",
                    fingerprint="fp-1",
                    tool="fake",
                    scanner_type="sast",
                    category="code",
                    title="Fake finding",
                    severity=Severity.LOW,
                )
            ]

    monkeypatch.setattr("secagent.core.orchestration.available_plugins", lambda: [FakePlugin()])
    monkeypatch.setattr(
        "secagent.core.orchestration.run_command",
        lambda command, timeout_seconds, cwd=None: CommandResult(return_code=0, stdout="{}", stderr="", duration_seconds=0.1),
    )

    config_path = tmp_path / "secagent.yml"
    output_dir = tmp_path / "reports"
    config_path.write_text(
        f"target: .\noutput_dir: {output_dir}\nreport:\n  formats: [json, html, sarif, md]\npolicy:\n  fail_on_severities: [CRITICAL]\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "--target", ".", "--config", str(config_path)])
    assert result.exit_code == 0
    assert (output_dir / "secagent-report.json").exists()
    assert (output_dir / "secagent-report.html").exists()
    assert (output_dir / "secagent-report.sarif").exists()
    assert (output_dir / "secagent-report.md").exists()
