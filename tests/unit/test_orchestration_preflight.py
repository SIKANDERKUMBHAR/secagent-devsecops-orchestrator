from pathlib import Path

from secagent.config.models import AppConfig
from secagent.core.orchestration import run_scan
from secagent.plugins.base import ScannerPlugin


class MissingBinaryPlugin(ScannerPlugin):
    name = "missing"
    scanner_type = "sast"
    category = "code"

    def is_enabled(self, config):
        return True

    def build_command(self, context):
        return ["missing-binary"]

    def parse(self, raw_output):
        return []

    def normalize(self, parsed_findings, include_raw=False):
        return []

    def required_binaries(self, config):
        return ["missing-binary"]


def test_scan_fails_fast_when_required_binary_missing(monkeypatch, tmp_path: Path) -> None:
    cfg = AppConfig()
    cfg.output_dir = tmp_path / "reports"
    cfg.runtime.work_dir = tmp_path / ".secagent-work"
    cfg.runtime.allow_partial_results = False

    monkeypatch.setattr("secagent.core.orchestration.available_plugins", lambda: [MissingBinaryPlugin()])
    monkeypatch.setattr("secagent.core.orchestration.shutil.which", lambda _name: None)

    report, exit_code = run_scan(target=str(tmp_path), app_config=cfg)
    assert exit_code == 3
    assert report.summary.total == 0
    assert report.scanner_runs[0].status == "error"
    assert "Missing required scanner binaries" in report.scanner_runs[0].errors[0]
