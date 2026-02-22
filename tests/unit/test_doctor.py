from secagent.core.doctor import ToolHealth, doctor_as_json, run_doctor


def test_doctor_json_shape() -> None:
    payload = doctor_as_json([
        ToolHealth(name="secagent", required=True, installed=True, path="/x/secagent", version="0.1.0")
    ])
    assert '"name": "secagent"' in payload


def test_doctor_missing_required(monkeypatch) -> None:
    monkeypatch.setattr("secagent.core.doctor.shutil.which", lambda _name: None)
    results, missing = run_doctor(["semgrep"])
    assert missing is True
    semgrep = next(item for item in results if item.name == "semgrep")
    assert semgrep.required is True
    assert semgrep.installed is False
