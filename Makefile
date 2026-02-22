.PHONY: install test scan docker-build docker-scan

install:
	pip install -e .[dev]

test:
	pytest --cov=secagent --cov-report=term-missing

scan:
	secagent scan --target . --config secagent.yml.example

docker-build:
	docker build -t secagent:local .

docker-scan:
	docker run --rm --user $$(id -u):$$(id -g) -v $(PWD):/workspace -w /workspace secagent:local scan --target /workspace --config /workspace/secagent.localtest.yml
