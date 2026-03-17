from secagent.config.models import ZapConfig
from secagent.core.zap_manager import ZapSession, cleanup_zap_session, ensure_zap_ready


def test_ensure_zap_ready_reuses_existing(monkeypatch) -> None:
    monkeypatch.setattr("secagent.core.zap_manager._zap_api_ready", lambda _url: True)
    cfg = ZapConfig(enabled=True)
    session = ensure_zap_ready(cfg)
    assert session.started_by_secagent is False


def test_ensure_zap_ready_autostart_disabled(monkeypatch) -> None:
    monkeypatch.setattr("secagent.core.zap_manager._zap_api_ready", lambda _url: False)
    cfg = ZapConfig(enabled=True, auto_start=False)
    try:
        ensure_zap_ready(cfg)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "auto_start is false" in str(exc)


def test_cleanup_only_when_started(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, check):
        calls.append(args)

        class Result:
            returncode = 0
            stderr = ""

        return Result()

    monkeypatch.setattr("secagent.core.zap_manager._run_docker", fake_run)
    cfg = ZapConfig(enabled=True, cleanup_after_scan=True)
    cleanup_zap_session(cfg, ZapSession(container_name="secagent-zap", started_by_secagent=False))
    assert calls == []
    cleanup_zap_session(cfg, ZapSession(container_name="secagent-zap", started_by_secagent=True))
    assert calls == [["rm", "-f", "secagent-zap"]]
