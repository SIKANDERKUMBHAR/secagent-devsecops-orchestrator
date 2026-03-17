"""Configuration schema models."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field


class ScannerToggleConfig(BaseModel):
    semgrep: bool = True
    gitleaks: bool = True
    trivy: bool = True
    checkov: bool = True
    zap: bool = False


class SemgrepConfig(BaseModel):
    config: str = "auto"
    timeout_seconds: int = 120


class GitleaksConfig(BaseModel):
    redact: bool = True
    timeout_seconds: int = 60


class TrivyConfig(BaseModel):
    scan_mode: str = "fs"
    severity: list[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    ignore_unfixed: bool = False
    timeout_seconds: int = 180
    cache_dir: str | None = None


class CheckovConfig(BaseModel):
    framework: list[str] = Field(default_factory=lambda: ["dockerfile", "terraform", "kubernetes"])
    timeout_seconds: int = 120


class ZapConfig(BaseModel):
    enabled: bool = False
    target_url: str = "http://app:3000"
    api_url: str = "http://zap:8080"
    auto_start: bool = True
    image: str = "ghcr.io/zaproxy/zaproxy:stable"
    fallback_image: str = "zaproxy/zap-stable"
    container_name: str = "secagent-zap"
    host_port: int = 8090
    zap_port: int = 8090
    cleanup_after_scan: bool = True
    api_key_env: str | None = None
    api_request_timeout_seconds: int = 20
    api_retries: int = 5
    api_retry_delay_seconds: float = 1.0
    timeout_seconds: int = 300


class PolicyConfig(BaseModel):
    fail_on_severities: list[str] = Field(default_factory=lambda: ["CRITICAL", "HIGH"])
    max_allowed: dict[str, int] = Field(default_factory=dict)
    fail_on_secrets: bool = True
    fail_on_new_only: bool = False


class BaselineConfig(BaseModel):
    path: Path = Path(".secagent-baseline.json")
    mode: str = "new_only"


class ReportConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["json", "html", "sarif", "md", "csv"])
    include_raw: bool = False
    theme: str = "default"


class SuppressionConfig(BaseModel):
    file: Path = Path(".secagent-suppressions.yml")
    reject_expired: bool = True


class RuntimeConfig(BaseModel):
    work_dir: Path = Path("./.secagent-work")
    keep_artifacts: bool = False
    parallelism: int = 4
    mask_secrets_in_logs: bool = True
    allow_partial_results: bool = False


class AppConfig(BaseModel):
    target: str = "."
    output_dir: Path = Path("./reports")
    profile: str = "ci"
    scanners: ScannerToggleConfig = ScannerToggleConfig()
    semgrep: SemgrepConfig = SemgrepConfig()
    gitleaks: GitleaksConfig = GitleaksConfig()
    trivy: TrivyConfig = TrivyConfig()
    checkov: CheckovConfig = CheckovConfig()
    zap: ZapConfig = ZapConfig()
    policy: PolicyConfig = PolicyConfig()
    baseline: BaselineConfig = BaselineConfig()
    suppressions: SuppressionConfig = SuppressionConfig()
    report: ReportConfig = ReportConfig()
    runtime: RuntimeConfig = RuntimeConfig()
