"""Lifecycle management for optional OWASP ZAP sidecar."""

from __future__ import annotations

import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from secagent.config.models import ZapConfig


@dataclass
class ZapSession:
    container_name: str
    started_by_secagent: bool


def ensure_zap_ready(config: ZapConfig) -> ZapSession:
    if _zap_api_ready(config.api_url):
        return ZapSession(container_name=config.container_name, started_by_secagent=False)

    if not config.auto_start:
        raise RuntimeError(
            "ZAP API is unreachable and zap.auto_start is false. "
            "Start ZAP manually or disable zap in config."
        )

    if not _is_local_api(config.api_url):
        raise RuntimeError(
            "ZAP auto-start is supported only for localhost API URLs. "
            "Set zap.api_url to localhost or start remote ZAP manually."
        )

    _require_docker()

    image = _pull_zap_image(config.image, config.fallback_image)
    _start_zap_container(config, image)
    _wait_for_api(config.api_url, timeout_seconds=120)
    return ZapSession(container_name=config.container_name, started_by_secagent=True)


def cleanup_zap_session(config: ZapConfig, session: ZapSession | None) -> None:
    if session is None:
        return
    if not session.started_by_secagent:
        return
    if not config.cleanup_after_scan:
        return
    _run_docker(["rm", "-f", session.container_name], check=False)


def stop_zap_container(container_name: str) -> None:
    _run_docker(["rm", "-f", container_name], check=False)


def zap_status(config: ZapConfig) -> tuple[bool, bool]:
    api_ok = _zap_api_ready(config.api_url)
    docker_ok = shutil.which("docker") is not None
    return api_ok, docker_ok


def _is_local_api(api_url: str) -> bool:
    host = urllib.parse.urlparse(api_url).hostname
    return host in {"127.0.0.1", "localhost"}


def _zap_api_ready(api_url: str) -> bool:
    url = api_url.rstrip("/") + "/JSON/core/view/version/"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310
            return response.status == 200
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ConnectionResetError, OSError, ValueError):
        return False


def _require_docker() -> None:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for zap.auto_start but was not found in PATH")


def _pull_zap_image(primary: str, fallback: str) -> str:
    if _run_docker(["pull", primary], check=False).returncode == 0:
        return primary
    if _run_docker(["pull", fallback], check=False).returncode == 0:
        return fallback
    raise RuntimeError(
        "Unable to pull ZAP image. Tried: "
        f"{primary}, {fallback}"
    )


def _start_zap_container(config: ZapConfig, image: str) -> None:
    _run_docker(["rm", "-f", config.container_name], check=False)
    command = [
        "run",
        "-d",
        "--name",
        config.container_name,
        "-p",
        f"{config.host_port}:{config.zap_port}",
        image,
        "zap.sh",
        "-daemon",
        "-host",
        "0.0.0.0",
        "-port",
        str(config.zap_port),
        "-config",
        "api.disablekey=true",
        "-config",
        "api.addrs.addr.name=.*",
        "-config",
        "api.addrs.addr.regex=true",
        "-config",
        "autoupdate.checkOnStart=false",
        "-config",
        "autoupdate.installAddonUpdates=false",
    ]
    result = _run_docker(command, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to start ZAP sidecar: {result.stderr.strip()}")


def _wait_for_api(api_url: str, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _zap_api_ready(api_url):
            return
        time.sleep(1.0)
    raise RuntimeError(f"ZAP API did not become ready at {api_url}")


def _run_docker(args: list[str], check: bool) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        check=check,
    )
