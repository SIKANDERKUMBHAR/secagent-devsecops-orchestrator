"""Resolve local or git repository scan targets."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse


@dataclass
class ResolvedTarget:
    original: str
    path: Path
    is_temp: bool = False


class TargetResolverError(ValueError):
    """Raised when target resolution fails."""


def resolve_target(target: str, work_dir: Path, token_env: str | None = None, ref: str | None = None) -> ResolvedTarget:
    if _looks_like_git_url(target):
        return _clone_repo(target, work_dir, token_env=token_env, ref=ref)

    path = Path(target)
    if not path.exists():
        raise TargetResolverError(f"Target path not found: {target}")
    return ResolvedTarget(original=target, path=path.resolve(), is_temp=False)


def cleanup_target(target: ResolvedTarget) -> None:
    if target.is_temp and target.path.exists():
        shutil.rmtree(target.path, ignore_errors=True)


def _looks_like_git_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://") or target.startswith("git@")


def _clone_repo(url: str, work_dir: Path, token_env: str | None = None, ref: str | None = None) -> ResolvedTarget:
    work_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = Path(tempfile.mkdtemp(prefix="secagent-clone-", dir=work_dir))
    clone_url = _tokenized_url(url, token_env)

    clone_cmd = ["git", "clone", clone_url, str(tmp_dir)]
    clone = subprocess.run(clone_cmd, capture_output=True, text=True, check=False)
    if clone.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise TargetResolverError(f"Git clone failed: {clone.stderr.strip()}")

    if ref:
        checkout = subprocess.run(["git", "checkout", ref], cwd=tmp_dir, capture_output=True, text=True, check=False)
        if checkout.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise TargetResolverError(f"Git checkout failed for ref '{ref}': {checkout.stderr.strip()}")

    return ResolvedTarget(original=url, path=tmp_dir, is_temp=True)


def _tokenized_url(url: str, token_env: str | None) -> str:
    if not token_env:
        return url
    token = os.getenv(token_env)
    if not token:
        raise TargetResolverError(f"Token env var not set: {token_env}")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return url
    host = parsed.hostname or ""
    netloc = f"x-access-token:{token}@{host}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
