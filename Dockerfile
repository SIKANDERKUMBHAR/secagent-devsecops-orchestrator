FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git wget gnupg \
    && rm -rf /var/lib/apt/lists/*

# semgrep
RUN pip install --no-cache-dir semgrep==1.84.0

# checkov + trivy python dependency compatibility
RUN pip install --no-cache-dir checkov==3.2.298

# gitleaks
RUN wget -qO- https://github.com/gitleaks/gitleaks/releases/download/v8.23.3/gitleaks_8.23.3_linux_x64.tar.gz \
    | tar -xz -C /usr/local/bin gitleaks

# trivy
RUN wget -qO- https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_Linux-64bit.tar.gz \
    | tar -xz -C /usr/local/bin trivy

WORKDIR /app
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 secagent
USER secagent

ENTRYPOINT ["secagent"]
CMD ["version"]
