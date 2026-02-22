"""Configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from secagent.config.models import AppConfig


class ConfigError(ValueError):
    """Raised when configuration is invalid."""


def load_config(config_path: Path | None) -> AppConfig:
    """Load application config from YAML file or defaults."""
    if config_path is None:
        return AppConfig()

    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        raw = _expand_short_config(raw)
        return AppConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"Invalid config: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"YAML parse error: {exc}") from exc


def _expand_short_config(raw: dict) -> dict:
    """Support a short, flat YAML shape by expanding to full schema."""
    if not isinstance(raw, dict):
        return raw

    expanded = dict(raw)

    scanners_val = expanded.get("scanners")
    if isinstance(scanners_val, list):
        enabled = {str(item).strip().lower() for item in scanners_val}
        expanded["scanners"] = {
            "semgrep": "semgrep" in enabled,
            "gitleaks": "gitleaks" in enabled,
            "trivy": "trivy" in enabled,
            "checkov": "checkov" in enabled,
            "zap": "zap" in enabled,
        }

    policy = dict(expanded.get("policy", {}))
    if "fail_on" in expanded and "fail_on_severities" not in policy:
        policy["fail_on_severities"] = expanded["fail_on"]
    if "fail_on_new_only" in expanded and "fail_on_new_only" not in policy:
        policy["fail_on_new_only"] = expanded["fail_on_new_only"]
    if "fail_on_secrets" in expanded and "fail_on_secrets" not in policy:
        policy["fail_on_secrets"] = expanded["fail_on_secrets"]
    if policy:
        expanded["policy"] = policy

    baseline = expanded.get("baseline")
    if isinstance(baseline, str):
        expanded["baseline"] = {"path": baseline, "mode": "new_only"}

    suppressions = expanded.get("suppressions")
    if isinstance(suppressions, str):
        expanded["suppressions"] = {"file": suppressions, "reject_expired": True}

    if "formats" in expanded:
        report = dict(expanded.get("report", {}))
        report.setdefault("formats", expanded["formats"])
        expanded["report"] = report

    if "parallelism" in expanded:
        runtime = dict(expanded.get("runtime", {}))
        runtime.setdefault("parallelism", expanded["parallelism"])
        expanded["runtime"] = runtime

    return expanded
