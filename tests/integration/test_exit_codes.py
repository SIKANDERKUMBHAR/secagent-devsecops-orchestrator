from pathlib import Path

from typer.testing import CliRunner

from secagent.cli import app
from secagent.constants import ExitCode, Severity
from secagent.core.runner import CommandResult

runner = CliRunner()


def _config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "secagent.yml"
    path.write_text(content, encoding="utf-8")
    return path


def test_policy_fail_exit_code(monkeypatch, tmp_path: Path) -> None:
    from secagent.plugins.base import ScannerPlugin
    from secagent.core.models import Finding

    class Plugin(ScannerPlugin):
        name = "p"
        scanner_type = "sast"
        category = "code"

        def is_enabled(self, config): return True
        def build_command(self, context): return ["p"]
        def parse(self, raw_output): return [{}]
        def normalize(self, parsed_findings, include_raw=False):
            return [Finding(id="1", fingerprint="fp", tool="p", scanner_type="sast", category="code", title="bad", severity=Severity.HIGH)]
        def required_binaries(self, config): return []

    monkeypatch.setattr("secagent.core.orchestration.available_plugins", lambda: [Plugin()])
    monkeypatch.setattr("secagent.core.orchestration.run_command", lambda *args, **kwargs: CommandResult(0, "{}", "", 0.1))
    cfg = _config(tmp_path, "policy:\n  fail_on_severities: [HIGH]\nreport:\n  formats: [json]\n")
    result = runner.invoke(app, ["scan", "--target", ".", "--config", str(cfg)])
    assert result.exit_code == ExitCode.POLICY_FAILED


def test_scanner_error_exit_code(monkeypatch, tmp_path: Path) -> None:
    from secagent.plugins.base import ScannerPlugin

    class Plugin(ScannerPlugin):
        name = "p"
        scanner_type = "sast"
        category = "code"

        def is_enabled(self, config): return True
        def build_command(self, context): return ["p"]
        def parse(self, raw_output): return []
        def normalize(self, parsed_findings, include_raw=False): return []
        def required_binaries(self, config): return []

    monkeypatch.setattr("secagent.core.orchestration.available_plugins", lambda: [Plugin()])
    monkeypatch.setattr("secagent.core.orchestration.run_command", lambda *args, **kwargs: CommandResult(2, "", "boom", 0.1))
    cfg = _config(tmp_path, "policy:\n  fail_on_severities: [CRITICAL]\nreport:\n  formats: [json]\n")
    result = runner.invoke(app, ["scan", "--target", ".", "--config", str(cfg)])
    assert result.exit_code == ExitCode.SCANNER_ERROR


def test_config_error_exit_code(tmp_path: Path) -> None:
    cfg = _config(tmp_path, "runtime:\n  parallelism: not-a-number\n")
    result = runner.invoke(app, ["scan", "--target", ".", "--config", str(cfg)])
    assert result.exit_code == ExitCode.CONFIG_ERROR
