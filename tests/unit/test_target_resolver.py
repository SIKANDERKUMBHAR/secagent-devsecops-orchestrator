from pathlib import Path

import pytest

from secagent.core.target_resolver import TargetResolverError, resolve_target


def test_resolve_local_target(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    resolved = resolve_target(str(target), work_dir=tmp_path)
    assert resolved.path == target.resolve()
    assert resolved.is_temp is False


def test_resolve_missing_target_raises(tmp_path: Path) -> None:
    with pytest.raises(TargetResolverError):
        resolve_target(str(tmp_path / "missing"), work_dir=tmp_path)
