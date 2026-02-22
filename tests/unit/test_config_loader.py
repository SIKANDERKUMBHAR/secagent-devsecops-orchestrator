from pathlib import Path

import pytest

from secagent.config.loader import ConfigError, load_config


def test_load_default_config_when_none() -> None:
    cfg = load_config(None)
    assert cfg.target == "."
    assert cfg.scanners.semgrep is True


def test_load_yaml_config(tmp_path: Path) -> None:
    config_file = tmp_path / "secagent.yml"
    config_file.write_text("target: ./app\nprofile: local\n", encoding="utf-8")

    cfg = load_config(config_file)
    assert cfg.target == "./app"
    assert cfg.profile == "local"


def test_missing_config_raises_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yml")


def test_load_short_config_shape(tmp_path: Path) -> None:
    config_file = tmp_path / "secagent.yml"
    config_file.write_text(
        "target: .\n"
        "scanners: [semgrep, trivy]\n"
        "formats: [json, html]\n"
        "fail_on: [CRITICAL, HIGH]\n"
        "baseline: .secagent-baseline.json\n"
        "parallelism: 2\n",
        encoding="utf-8",
    )
    cfg = load_config(config_file)
    assert cfg.scanners.semgrep is True
    assert cfg.scanners.trivy is True
    assert cfg.scanners.gitleaks is False
    assert cfg.report.formats == ["json", "html"]
    assert cfg.policy.fail_on_severities == ["CRITICAL", "HIGH"]
    assert str(cfg.baseline.path) == ".secagent-baseline.json"
    assert cfg.runtime.parallelism == 2
