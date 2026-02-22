# Development

## Local Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Run Tests

```bash
pytest --cov=secagent --cov-report=term-missing
```

## Linting

Add your preferred linter (ruff/black) in CI for future releases.

## Release Steps

1. Update `CHANGELOG.md`.
2. Bump version in `pyproject.toml` and `src/secagent/__init__.py`.
3. Run tests.
4. Build Docker image and smoke test.
5. Tag release and publish artifacts.
