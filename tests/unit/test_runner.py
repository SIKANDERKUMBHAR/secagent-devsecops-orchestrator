from secagent.core.runner import run_command


def test_run_command_timeout_returns_structured_result() -> None:
    result = run_command(["python3", "-c", "import time; time.sleep(2)"], timeout_seconds=1)
    assert result.return_code == 124
    assert "timed out" in result.stderr.lower()
