import json
from pathlib import Path

from typer.testing import CliRunner

from secagent.cli import app
from secagent.constants import Severity
from secagent.core.runner import CommandResult

runner = CliRunner()


def test_report_finding_order_is_deterministic(monkeypatch, tmp_path: Path) -> None:
    from secagent.core.models import Finding
    from secagent.plugins.base import ScannerPlugin

    class Plugin(ScannerPlugin):
        name = "p"
        scanner_type = "sast"
        category = "code"

        def is_enabled(self, config): return True
        def build_command(self, context): return ["p"]
        def parse(self, raw_output): return [{}]
        def normalize(self, parsed_findings, include_raw=False):
            return [
                Finding(id="2", fingerprint="b", tool="p", scanner_type="sast", category="code", title="zeta", severity=Severity.LOW),
                Finding(id="1", fingerprint="a", tool="p", scanner_type="sast", category="code", title="alpha", severity=Severity.HIGH),
            ]

    monkeypatch.setattr("secagent.core.orchestration.available_plugins", lambda: [Plugin()])
    monkeypatch.setattr("secagent.core.orchestration.run_command", lambda *args, **kwargs: CommandResult(0, "{}", "", 0.1))

    config_path = tmp_path / "secagent.yml"
    output_dir = tmp_path / "reports"
    config_path.write_text(
        f"target: .\noutput_dir: {output_dir}\nreport:\n  formats: [json]\npolicy:\n  fail_on_severities: [CRITICAL]\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", "--target", ".", "--config", str(config_path)])
    assert result.exit_code == 0
    payload = json.loads((output_dir / "secagent-report.json").read_text(encoding="utf-8"))
    assert payload["findings"][0]["title"] == "alpha"
