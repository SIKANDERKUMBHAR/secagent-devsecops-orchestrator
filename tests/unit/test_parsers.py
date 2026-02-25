import json
from pathlib import Path

import pytest

from secagent.config.models import AppConfig
from secagent.plugins.checkov import CheckovPlugin
from secagent.plugins.gitleaks import GitleaksPlugin
from secagent.plugins.base import ScanContext
from secagent.plugins.semgrep import SemgrepPlugin
from secagent.plugins.trivy import TrivyPlugin


def _load_fixture(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_semgrep_parser_fixture() -> None:
    plugin = SemgrepPlugin()
    raw = _load_fixture(Path("tests/fixtures/semgrep/results.json"))
    parsed = plugin.parse(raw)
    findings = plugin.normalize(parsed)
    assert len(findings) == 1
    assert findings[0].tool == "semgrep"
    assert findings[0].severity.value in {"HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO", "UNKNOWN"}
    assert findings[0].metadata["rule_id"] == "python.lang.security.audit.eval-detected"


def test_gitleaks_parser_fixture_masks_secret() -> None:
    plugin = GitleaksPlugin()
    raw = _load_fixture(Path("tests/fixtures/gitleaks/results.json"))
    parsed = plugin.parse(raw)
    findings = plugin.normalize(parsed)
    assert len(findings) == 1
    assert findings[0].scanner_type == "secrets"
    assert findings[0].evidence["secret"] == "***"
    assert "abcd1234" not in json.dumps(findings[0].model_dump(mode="json"))


def test_trivy_parser_fixture() -> None:
    plugin = TrivyPlugin()
    raw = _load_fixture(Path("tests/fixtures/trivy/results.json"))
    parsed = plugin.parse(raw)
    findings = plugin.normalize(parsed)
    assert len(findings) == 1
    assert findings[0].package_name == "flask"
    assert findings[0].cve_ids == ["CVE-2024-0001"]


def test_trivy_misconfig_and_secret_normalization() -> None:
    plugin = TrivyPlugin()
    parsed = [
        {
            "__kind": "misconfiguration",
            "ID": "AVD-DS-0002",
            "Title": "Missing USER",
            "Severity": "MEDIUM",
            "Target": "Dockerfile",
        },
        {
            "__kind": "secret",
            "RuleID": "aws-access-key-id",
            "Title": "AWS Access Key",
            "Severity": "HIGH",
            "Match": "AKIA1234567890TEST",
            "Target": "app/.env",
        },
    ]
    findings = plugin.normalize(parsed)
    assert findings[0].scanner_type == "iac"
    assert findings[0].category == "misconfiguration"
    assert findings[1].scanner_type == "secrets"
    assert findings[1].evidence.get("secret") == "***"


def test_checkov_parser_fixture() -> None:
    plugin = CheckovPlugin()
    raw = _load_fixture(Path("tests/fixtures/checkov/results.json"))
    parsed = plugin.parse(raw)
    findings = plugin.normalize(parsed)
    assert len(findings) == 1
    assert findings[0].metadata["rule_id"] == "CKV_DOCKER_2"
    assert findings[0].line_start == 1


def test_unknown_severity_maps_to_unknown() -> None:
    plugin = CheckovPlugin()
    parsed = [{"check_id": "X", "check_name": "x", "severity": "banana", "file_line_range": [1, 1]}]
    findings = plugin.normalize(parsed)
    assert findings[0].severity.value == "UNKNOWN"


def test_no_findings_payloads() -> None:
    assert SemgrepPlugin().parse("{}") == []
    assert TrivyPlugin().parse("{}") == []
    assert CheckovPlugin().parse("{}") == []
    assert GitleaksPlugin().parse("") == []


def test_malformed_json_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        SemgrepPlugin().parse("{invalid")


def test_nonzero_exit_semantics() -> None:
    from secagent.core.runner import CommandResult

    result = CommandResult(return_code=1, stdout="", stderr="", duration_seconds=0.1)
    assert SemgrepPlugin().is_success_return_code(result) is True
    assert GitleaksPlugin().is_success_return_code(result) is True
    assert CheckovPlugin().is_success_return_code(result) is True
    assert TrivyPlugin().is_success_return_code(result) is False


def test_checkov_missing_description_is_handled() -> None:
    plugin = CheckovPlugin()
    parsed = [{"check_id": "CKV_X", "check_name": "x", "description": None, "file_line_range": []}]
    findings = plugin.normalize(parsed)
    assert findings[0].description == ""


def test_trivy_command_uses_writable_cache_dir(tmp_path: Path) -> None:
    plugin = TrivyPlugin()
    cfg = AppConfig()
    context = ScanContext(target=str(tmp_path), output_dir=tmp_path, work_dir=tmp_path / ".secagent-work", config=cfg)
    command = plugin.build_command(context)
    assert "--cache-dir" in command
