from pathlib import Path

import pytest

from secagent.config.models import AppConfig
from secagent.plugins.zap import ZapPlugin, _should_retry_status


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


def test_zap_retryable_statuses() -> None:
    assert _should_retry_status(502) is True
    assert _should_retry_status(503) is True
    assert _should_retry_status(429) is True
    assert _should_retry_status(404) is False


def test_wait_until_ready_retries_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    plugin = ZapPlugin()
    attempts = {"count": 0}

    def fake_api_get_json(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("temporary upstream failure")
        return {"version": "2.15.0"}

    monkeypatch.setattr("secagent.plugins.zap._api_get_json", fake_api_get_json)
    plugin._wait_until_ready("http://127.0.0.1:8090", timeout_seconds=5, apikey=None, request_timeout_seconds=1)
    assert attempts["count"] == 3
