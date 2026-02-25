"""Scan orchestration engine."""

from __future__ import annotations

import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from secagent import __version__
from secagent.config.models import AppConfig
from secagent.constants import ExitCode, SCHEMA_VERSION_REPORT
from secagent.core.baseline import apply_baseline, load_baseline
from secagent.core.dedupe import dedupe_findings
from secagent.core.models import Finding, ReportMetadata, ScannerRun, SuppressionSummary, UnifiedReport
from secagent.core.normalize import build_summary, sort_findings
from secagent.core.policy import evaluate_policy
from secagent.core.runner import run_command
from secagent.core.suppression import apply_suppressions, load_suppressions
from secagent.core.target_resolver import cleanup_target, resolve_target
from secagent.plugins.base import ScanContext, ScannerPlugin
from secagent.plugins.checkov import CheckovPlugin
from secagent.plugins.gitleaks import GitleaksPlugin
from secagent.plugins.semgrep import SemgrepPlugin
from secagent.plugins.trivy import TrivyPlugin
from secagent.plugins.zap import ZapPlugin
from secagent.utils.masking import mask_secrets


def available_plugins() -> list[ScannerPlugin]:
    return [SemgrepPlugin(), GitleaksPlugin(), TrivyPlugin(), CheckovPlugin(), ZapPlugin()]


def run_scan(
    target: str,
    app_config: AppConfig,
    baseline_path: Path | None = None,
    suppressions_path: Path | None = None,
    token_env: str | None = None,
    ref: str | None = None,
) -> tuple[UnifiedReport, int]:
    output_dir = Path(app_config.output_dir)
    work_dir = Path(app_config.runtime.work_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    resolved = resolve_target(target, work_dir=work_dir, token_env=token_env, ref=ref)
    context = ScanContext(target=str(resolved.path), output_dir=output_dir, work_dir=work_dir, config=app_config)

    scanner_runs: list[ScannerRun] = []
    findings: list[Finding] = []
    scanner_error = False
    enabled_plugins = [plugin for plugin in available_plugins() if plugin.is_enabled(app_config)]

    runnable_plugins: list[ScannerPlugin] = []
    for plugin in enabled_plugins:
        missing_bins = [name for name in plugin.required_binaries(app_config) if shutil.which(name) is None]
        if not missing_bins:
            runnable_plugins.append(plugin)
            continue

        scanner_runs.append(
            ScannerRun(
                scanner=plugin.name,
                status="error",
                errors=[f"Missing required scanner binaries: {', '.join(missing_bins)}"],
            )
        )
        scanner_error = True

    if scanner_error and not app_config.runtime.allow_partial_results:
        baseline_set = load_baseline(baseline_path) if baseline_path else set()
        baseline_diff = apply_baseline(findings, baseline_set, str(baseline_path) if baseline_path else None)
        policy_result = evaluate_policy(findings, app_config.policy)
        report = UnifiedReport(
            metadata=ReportMetadata(
                schema_version=SCHEMA_VERSION_REPORT,
                generated_at=datetime.now(timezone.utc),
                target=target,
                profile=app_config.profile,
                secagent_version=__version__,
            ),
            scanner_runs=sorted(scanner_runs, key=lambda s: s.scanner),
            findings=findings,
            summary=build_summary(findings),
            policy=policy_result,
            baseline=baseline_diff,
            suppressions=SuppressionSummary(),
            diagnostics={"enabled_scanners": [p.name for p in enabled_plugins], "partial_results": False},
        )
        cleanup_target(resolved)
        return report, int(ExitCode.SCANNER_ERROR)

    try:
        with ThreadPoolExecutor(max_workers=max(1, app_config.runtime.parallelism)) as pool:
            future_map = {pool.submit(_run_single_plugin, plugin, context): plugin for plugin in runnable_plugins}
            for future in as_completed(future_map):
                plugin = future_map[future]
                try:
                    run_info, plugin_findings, failed = future.result()
                    scanner_runs.append(run_info)
                    findings.extend(plugin_findings)
                    scanner_error = scanner_error or failed
                except Exception as exc:  # pragma: no cover
                    scanner_runs.append(
                        ScannerRun(
                            scanner=plugin.name,
                            status="error",
                            errors=[str(exc)],
                        )
                    )
                    scanner_error = True
    finally:
        cleanup_target(resolved)

    unique, _duplicates = dedupe_findings(findings)
    unique = sort_findings(unique)

    baseline_set = load_baseline(baseline_path) if baseline_path else set()
    baseline_diff = apply_baseline(unique, baseline_set, str(baseline_path) if baseline_path else None)

    suppression_summary = SuppressionSummary()
    if suppressions_path:
        rules = load_suppressions(suppressions_path)
        suppression_summary = apply_suppressions(unique, rules, reject_expired=app_config.suppressions.reject_expired)

    policy_result = evaluate_policy(unique, app_config.policy)
    exit_code = policy_result.exit_code
    if scanner_error and exit_code == ExitCode.SUCCESS:
        exit_code = ExitCode.SCANNER_ERROR

    report = UnifiedReport(
        metadata=ReportMetadata(
            schema_version=SCHEMA_VERSION_REPORT,
            generated_at=datetime.now(timezone.utc),
            target=target,
            profile=app_config.profile,
            secagent_version=__version__,
        ),
        scanner_runs=sorted(scanner_runs, key=lambda s: s.scanner),
        findings=unique,
        summary=build_summary(unique),
        policy=policy_result,
        baseline=baseline_diff,
        suppressions=suppression_summary,
        diagnostics={"enabled_scanners": [p.name for p in enabled_plugins]},
    )
    return report, int(exit_code)


def _run_single_plugin(plugin: ScannerPlugin, context: ScanContext) -> tuple[ScannerRun, list[Finding], bool]:
    custom = plugin.run(context)
    if custom is not None:
        return custom

    command = plugin.build_command(context)
    result = run_command(command, timeout_seconds=plugin.timeout_seconds(context.config))
    parse_source = result.stdout

    if plugin.name == "gitleaks" and not result.stdout.strip():
        expected_path = context.work_dir / "gitleaks.json"
        if expected_path.exists():
            parse_source = expected_path.read_text(encoding="utf-8")

    findings = plugin.normalize(plugin.parse(parse_source), include_raw=context.config.report.include_raw)
    success = plugin.is_success_return_code(result)
    run = ScannerRun(
        scanner=plugin.name,
        status="ok" if success else "error",
        duration_seconds=result.duration_seconds,
        command=mask_secrets(" ".join(command)),
        return_code=result.return_code,
        errors=[mask_secrets(result.stderr)] if (result.stderr and not success) else [],
    )
    return run, findings, not success


def write_json_report(report: UnifiedReport, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2), encoding="utf-8")
