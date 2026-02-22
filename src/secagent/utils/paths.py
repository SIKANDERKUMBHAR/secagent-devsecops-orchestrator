"""Path utility helpers."""

from __future__ import annotations

from pathlib import Path


def normalize_path(path: str, base: Path | None = None) -> str:
    base_dir = base or Path.cwd()
    return str((base_dir / path).resolve()) if not Path(path).is_absolute() else str(Path(path).resolve())
