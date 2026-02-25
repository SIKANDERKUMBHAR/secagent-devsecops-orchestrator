from pathlib import Path

from secagent.config.models import AppConfig
from secagent.plugins.zap import ZapPlugin


def test_zap_parse_and_normalize_fixture() -> None:
    plugin = ZapPlugin()
    raw = Path("tests/fixtures/zap/alerts.json").read_text(encoding="utf-8")
    parsed = plugin.parse(raw)
    findings = plugin.normalize(parsed)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool == "zap"
    assert finding.scanner_type == "dast"
    assert finding.severity.value == "HIGH"
    assert finding.cwe_ids == ["CWE-79"]
    assert finding.resource == "http://app:3000/search?q=test"


def test_zap_plugin_enablement() -> None:
    plugin = ZapPlugin()
    cfg = AppConfig()
    assert plugin.is_enabled(cfg) is False
    cfg.scanners.zap = True
    cfg.zap.enabled = True
    assert plugin.is_enabled(cfg) is True
