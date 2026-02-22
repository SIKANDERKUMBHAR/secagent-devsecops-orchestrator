"""Command-line interface for SecAgent."""

from __future__ import annotations

from pathlib import Path
import json

import typer
from rich.console import Console

from secagent import __version__
from secagent.config.loader import ConfigError, load_config
from secagent.constants import ExitCode
from secagent.core.baseline import create_baseline_file
from secagent.core.doctor import doctor_as_json, run_doctor
from secagent.core.orchestration import run_scan
from secagent.logging_utils import configure_logging
from secagent.reports.html_report import render_html_report
from secagent.reports.json_report import write_json
from secagent.reports.markdown_report import write_markdown
from secagent.reports.sarif_report import write_sarif

app = typer.Typer(help="SecAgent security orchestrator CLI")
baseline_app = typer.Typer(help="Baseline management")
app.add_typer(baseline_app, name="baseline")
console = Console()


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", help="Enable debug logs"),
    quiet: bool = typer.Option(False, "--quiet", help="Only print errors"),
    log_file: Path | None = typer.Option(None, "--log-file", help="Optional log file path"),
) -> None:
    """Global CLI options."""
    configure_logging(verbose=verbose, quiet=quiet, log_file=log_file)


@app.command("version")
def version() -> None:
    """Print application version."""
    console.print(__version__)


@app.command("validate-config")
def validate_config(config: Path = typer.Option(..., "--config", exists=True, readable=True)) -> None:
    """Validate YAML configuration file."""
    try:
        _ = load_config(config)
    except ConfigError as exc:
        console.print(f"[red]Config validation failed:[/red] {exc}")
        raise typer.Exit(code=ExitCode.CONFIG_ERROR)

    console.print("[green]Configuration is valid.[/green]")


@app.command("scan")
def scan(
    target: str = typer.Option(".", "--target", help="Path or Git URL to scan"),
    config: Path | None = typer.Option(None, "--config", help="Config YAML file"),
    baseline: Path | None = typer.Option(None, "--baseline", help="Baseline JSON file"),
    suppressions: Path | None = typer.Option(None, "--suppressions", help="Suppressions YAML file"),
    token_env: str | None = typer.Option(None, "--token-env", help="Env var name containing VCS token"),
    ref: str | None = typer.Option(None, "--ref", help="Git branch/tag/commit when target is URL"),
) -> None:
    """Run security scan orchestration."""
    try:
        app_config = load_config(config)
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.CONFIG_ERROR)

    baseline_path = baseline or app_config.baseline.path
    suppressions_path = suppressions or app_config.suppressions.file
    try:
        report, exit_code = run_scan(
            target=target,
            app_config=app_config,
            baseline_path=baseline_path,
            suppressions_path=suppressions_path if suppressions_path.exists() else None,
            token_env=token_env,
            ref=ref,
        )
    except Exception as exc:
        console.print(f"[red]Internal error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INTERNAL_ERROR)

    output_dir = Path(app_config.output_dir)
    formats = {fmt.lower() for fmt in app_config.report.formats}
    json_path = output_dir / "secagent-report.json"
    html_path = output_dir / "secagent-report.html"
    sarif_path = output_dir / "secagent-report.sarif"
    md_path = output_dir / "secagent-report.md"

    if "json" in formats:
        write_json(report, json_path)
    if "html" in formats:
        render_html_report(report, html_path)
    if "sarif" in formats:
        write_sarif(report, sarif_path)
    if "md" in formats or "markdown" in formats:
        write_markdown(report, md_path)

    console.print(f"Findings: {report.summary.total}")
    console.print(f"Policy: {'PASS' if report.policy.passed else 'FAIL'}")
    console.print(f"Output: {output_dir}")
    raise typer.Exit(code=exit_code)


@app.command("report")
def report(input_json: Path = typer.Option(..., "--input-json"), output_html: Path = typer.Option(..., "--output-html")) -> None:
    """Render HTML report from existing JSON report."""
    from secagent.core.models import UnifiedReport

    payload = json.loads(input_json.read_text(encoding="utf-8"))
    report_model = UnifiedReport.model_validate(payload)
    render_html_report(report_model, output_html)
    console.print(f"HTML report written: {output_html}")


@app.command("doctor")
def doctor(
    config: Path | None = typer.Option(None, "--config", help="Optional config to determine required scanners"),
    as_json: bool = typer.Option(False, "--json", help="Output machine-readable JSON"),
) -> None:
    """Diagnose local secagent and scanner environment health."""
    try:
        app_config = load_config(config)
    except ConfigError as exc:
        console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.CONFIG_ERROR)

    enabled_scanners = [
        name
        for name, enabled in {
            "semgrep": app_config.scanners.semgrep,
            "gitleaks": app_config.scanners.gitleaks,
            "trivy": app_config.scanners.trivy,
            "checkov": app_config.scanners.checkov,
            "zap": app_config.scanners.zap,
        }.items()
        if enabled
    ]
    results, missing_required = run_doctor(enabled_scanners)

    if as_json:
        console.print(doctor_as_json(results))
    else:
        for item in results:
            req = "required" if item.required else "optional"
            status = "OK" if item.installed and not item.error else "MISSING" if not item.installed else "WARN"
            console.print(f"[{status}] {item.name} ({req})")
            if item.path:
                console.print(f"  path: {item.path}")
            if item.version:
                console.print(f"  version: {item.version}")
            if item.error:
                console.print(f"  note: {item.error}")

    raise typer.Exit(code=ExitCode.SCANNER_ERROR if missing_required else ExitCode.SUCCESS)


@baseline_app.command("create")
def baseline_create(
    input_json: Path = typer.Option(..., "--input-json", help="Scan JSON report"),
    output: Path = typer.Option(Path(".secagent-baseline.json"), "--output", help="Baseline path"),
) -> None:
    """Create baseline from an existing JSON report."""
    from secagent.core.models import UnifiedReport

    payload = json.loads(input_json.read_text(encoding="utf-8"))
    report_model = UnifiedReport.model_validate(payload)
    create_baseline_file(output, report_model.findings, report_model.metadata.target)
    console.print(f"Baseline created at {output}")


@baseline_app.command("update")
def baseline_update(
    input_json: Path = typer.Option(..., "--input-json", help="Scan JSON report"),
    output: Path = typer.Option(Path(".secagent-baseline.json"), "--output", help="Baseline path"),
) -> None:
    """Update baseline from an existing JSON report."""
    baseline_create(input_json=input_json, output=output)
