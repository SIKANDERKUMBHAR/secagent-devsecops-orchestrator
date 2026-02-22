# Architecture

## Module Flow

1. CLI parses args and loads YAML config.
2. Target resolver maps local path or clones git URL to work dir.
3. Orchestration engine discovers enabled scanner plugins.
4. Plugins run in parallel via shared subprocess runner.
5. Plugin parsers normalize scanner outputs into `Finding` schema.
6. Dedupe, baseline labeling, and suppressions are applied.
7. Policy engine evaluates findings and decides exit code.
8. Report generators emit JSON, HTML, and SARIF.

## Boundaries

- `secagent.cli`: command layer only.
- `secagent.config`: external YAML schema and validation.
- `secagent.plugins`: scanner adapters and parsers.
- `secagent.core`: orchestration + policy + baseline + suppression.
- `secagent.reports`: output format renderers.
- `secagent.utils`: masking and path-safe helpers.

## Security Defaults

- Secret masking in command logs and gitleaks evidence.
- No shell execution in scanner subprocesses.
- Temporary clone directories for remote targets.
- Expired suppressions rejected by default.
