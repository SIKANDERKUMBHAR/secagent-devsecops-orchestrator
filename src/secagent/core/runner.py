"""Shared subprocess execution for scanner plugins."""

from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass


@dataclass
class CommandResult:
    return_code: int
    stdout: str
    stderr: str
    duration_seconds: float


def run_command(command: list[str], timeout_seconds: int, cwd: str | None = None) -> CommandResult:
    start = time.monotonic()
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=cwd,
            check=False,
        )
        duration = time.monotonic() - start
        return CommandResult(
            return_code=process.returncode,
            stdout=process.stdout,
            stderr=process.stderr,
            duration_seconds=duration,
        )
    except subprocess.TimeoutExpired as exc:
        duration = time.monotonic() - start
        return CommandResult(
            return_code=124,
            stdout=exc.stdout or "",
            stderr=f"Command timed out after {timeout_seconds} seconds",
            duration_seconds=duration,
        )
