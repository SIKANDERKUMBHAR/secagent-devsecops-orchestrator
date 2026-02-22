from typer.testing import CliRunner

from secagent.cli import app
from secagent.constants import ExitCode

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.stdout


def test_validate_config_ok(tmp_path) -> None:
    config_file = tmp_path / "secagent.yml"
    config_file.write_text("target: .\n", encoding="utf-8")
    result = runner.invoke(app, ["validate-config", "--config", str(config_file)])
    assert result.exit_code == 0
    assert "Configuration is valid" in result.stdout


def test_validate_config_bad_file_path(tmp_path) -> None:
    missing = tmp_path / "nope.yml"
    result = runner.invoke(app, ["validate-config", "--config", str(missing)])
    assert result.exit_code == ExitCode.CONFIG_ERROR
