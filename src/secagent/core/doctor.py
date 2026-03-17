"""Environment diagnostics for secagent and scanner dependencies."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

from secagent import __version__


@dataclass
class ToolHealth:
    name: str
    required: bool
    installed: bool
    path: str | None
    version: str | None
    error: str | None = None


def run_doctor(enabled_scanners: list[str]) -> tuple[list[ToolHealth], bool]:
    """Check whether required scanner binaries are installed and callable."""
    checks = [
        _check_secagent(),
    ]

    scanner_tools = {
        "semgrep": {"version_args": ["--version"], "optional": False},
        "gitleaks": {"version_args": ["version"], "optional": False},
        "trivy": {"version_args": ["--version"], "optional": False},
        "checkov": {"version_args": ["--version"], "optional": False},
        # ZAP runs in API sidecar mode for secagent, so local binary is optional.
        "zap": {"version_args": ["-version"], "optional": True},
    }

    missing_required = False
    for scanner, metadata in scanner_tools.items():
        required = scanner in enabled_scanners and not metadata["optional"]
        health = _check_tool(scanner, required=required, version_args=metadata["version_args"])
        if required and not health.installed:
            missing_required = True
        checks.append(health)

    return checks, missing_required


def doctor_as_json(results: list[ToolHealth]) -> str:
    return json.dumps([asdict(item) for item in results], indent=2)


def _check_tool(name: str, required: bool, version_args: list[str]) -> ToolHealth:
    path = shutil.which(name)
    if not path:
        return ToolHealth(
            name=name,
            required=required,
            installed=False,
            path=None,
            version=None,
            error="not found in PATH",
        )

    try:
        process = subprocess.run(
            [name, *version_args],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        output = (process.stdout or process.stderr or "").strip().splitlines()
        version_line = output[0] if output else "unknown"
        return ToolHealth(
            name=name,
            required=required,
            installed=True,
            path=path,
            version=version_line,
            error=None if process.returncode in (0, 1) else f"version command exit {process.returncode}",
        )
    except Exception as exc:  # pragma: no cover
        return ToolHealth(
            name=name,
            required=required,
            installed=True,
            path=path,
            version=None,
            error=str(exc),
        )


def _check_secagent() -> ToolHealth:
    return ToolHealth(
        name="secagent",
        required=True,
        installed=True,
        path=str(Path(__file__).resolve()),
        version=__version__,
        error=None,
    )
