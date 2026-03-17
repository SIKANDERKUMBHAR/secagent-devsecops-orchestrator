# secagent

`secagent` is a production-ready DevSecOps security orchestration CLI. It runs multiple scanners in one command, normalizes findings into a unified schema, applies policy/baseline/suppressions, and generates JSON/HTML/SARIF outputs for local use and CI/CD.

## Features

- Multi-scanner orchestration: Semgrep, Gitleaks, Trivy, Checkov, and OWASP ZAP (sidecar/API mode).
- Canonical finding model with deterministic fingerprints.
- Deduplication and policy enforcement with stable CI exit codes.
- Baseline mode (`new` vs `baselined`) for incremental adoption.
- Suppression rules with required reason + expiry.
- Outputs: unified JSON, human-readable HTML, SARIF 2.1.0.
- Parallel scanner execution and scanner diagnostics.
- Secure defaults: masked secrets and sanitized command logging.

## Installation

### Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Docker

```bash
docker build -t secagent:local .
```

## Quickstart

```bash
secagent validate-config --config secagent.yml.example
secagent scan --target . --config secagent.yml.example
```

Reports are written to `reports/` by default:

- `reports/secagent-report.json`
- `reports/secagent-report.html`
- `reports/secagent-report.sarif`

## Exact Commands

Install:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

Test:

```bash
pytest --cov=secagent --cov-report=term-missing
```

Local scan (fixture-safe / no scanner binaries required):

```bash
secagent scan --target . --config secagent.localtest.yml
```

Docker build + run:

```bash
docker build -t secagent:local .
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd)":/workspace -w /workspace secagent:local scan --target /workspace --config /workspace/secagent.yml.example
```

Pull from Docker Hub + verify:

```bash
docker pull sikanderali/secagent:latest
docker run --rm sikanderali/secagent:latest version
```

One-command local setup (no Docker):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/SIKANDERKUMBHAR/secagent-devsecops-orchestrator/main/scripts/setup-local.sh)
```

Optional ZAP sidecar install/start:

```bash
scripts/install-zap.sh --start
```

If `zap.enabled: true`, `secagent scan` can auto-start a local ZAP sidecar when `zap.api_url` points to localhost.

GitHub Actions usage notes:

```bash
gh workflow run secagent-ci.yml
gh run list --workflow secagent-ci.yml
gh run view --log
```

ZAP diagnostics (single-run connectivity + container checks):

```bash
scripts/zap-diagnostics.sh --api-url http://127.0.0.1:8090 --target-url http://127.0.0.1:3000 --config /home/ubuntu/secagent/secagent-dast.yml
```

## CLI

- `secagent scan --target . --config secagent.yml`
- `secagent scan --target https://github.com/org/repo.git --token-env GITHUB_TOKEN --ref main`
- `secagent report --input-json reports/secagent-report.json --output-html reports/custom.html`
- `secagent baseline create --input-json reports/secagent-report.json --output .secagent-baseline.json`
- `secagent validate-config --config secagent.yml`
- `secagent doctor --config secagent.yml`
- `secagent zap start --config secagent.yml`
- `secagent zap status --config secagent.yml`
- `secagent zap stop --config secagent.yml`
- `secagent version`

## Config

Use `secagent.yml.example` as a starter.

Short config (recommended):

```yaml
target: .
output_dir: ./reports
scanners: [semgrep, gitleaks, trivy, checkov]
formats: [json, html, sarif, md, csv]
fail_on: [CRITICAL, HIGH]
baseline: .secagent-baseline.json
```

Advanced nested config is still supported for scanner-specific options and fine-grained runtime tuning.

## Exit Codes

- `0`: scan completed and policy passed
- `1`: scan completed and policy failed
- `2`: config/CLI validation error
- `3`: scanner execution error
- `4`: internal application error

## Baseline Mode

1. Run a scan and create baseline:

```bash
secagent baseline create --input-json reports/secagent-report.json --output .secagent-baseline.json
```

2. Re-scan with baseline:

```bash
secagent scan --target . --config secagent.yml.example --baseline .secagent-baseline.json
```

Findings are labeled as `new` or `baselined`; policy can be configured to fail on new only.

## Suppressions

Example `.secagent-suppressions.yml`:

```yaml
suppressions:
  - fingerprint: "<fingerprint>"
    reason: "False positive in wrapper"
    expires: "2026-12-31"
    tools: ["semgrep"]
  - rule_id: "CKV_DOCKER_2"
    path_glob: "examples/**"
    reason: "Example code only"
    expires: "2026-06-30"
```

## Architecture

See `docs/architecture.md`.

## Development

See `docs/development.md`.

## CI Example

GitHub Actions workflow is provided at `.github/workflows/secagent-ci.yml`.

## Limitations (v1)

- ZAP support is baseline/API mode for CI-safe DAST; full authenticated active scanning is planned.
- Trivy image scan mode is planned; filesystem mode is implemented.
- Full SARIF enrichment can be extended further.
