# Simple Guide: Why These Security Tools Matter

This file explains, in simple words, why `secagent` uses these tools:

- Semgrep
- Gitleaks
- Trivy
- Checkov

It also explains:

- Baseline Adoption Mode
- Suppressions (Governed Exceptions)

---

## 1) Semgrep (Code Security / SAST)

### What it checks
Semgrep scans your source code and finds risky patterns.

### Simple example
- It can detect dangerous code like `eval(user_input)`.
- It can detect weak security checks or insecure API usage.

### Why we use it
- Fast code-level security checks.
- Good for catching developer mistakes early.

---

## 2) Gitleaks (Secrets Detection)

### What it checks
Gitleaks finds secrets accidentally committed in code.

### Simple example
- AWS keys in `.env` files
- Private keys in repo
- Hardcoded API tokens in code

### Why we use it
- Secrets leaks are high-risk and easy to miss manually.
- Helps prevent credential compromise.

---

## 3) Trivy (Vulnerabilities in Dependencies/Images/Files)

### What it checks
Trivy scans dependencies and system packages for known CVEs.

### Simple example
- Your app uses a library version with known CVE.
- A base image package is vulnerable.

### Why we use it
- Dependency risk is one of the biggest real-world attack paths.
- Gives severity and fixed version guidance.

---

## 4) Checkov (IaC & Dockerfile Misconfiguration)

### What it checks
Checkov scans infrastructure files and Dockerfiles for bad security settings.

### Simple example
- Dockerfile missing non-root user
- Dockerfile missing HEALTHCHECK
- Cloud/IaC config exposing risky permissions

### Why we use it
- Prevents insecure infrastructure from reaching production.
- Catches config mistakes before deployment.

---

## Why combine all 4 tools?

Each tool covers different risk types:

- Semgrep: code logic issues
- Gitleaks: leaked secrets
- Trivy: known vulnerabilities in dependencies/packages
- Checkov: infrastructure and container misconfiguration

Using only one tool gives partial security coverage.
Using all four gives better practical DevSecOps coverage.

---

## Baseline Adoption Mode (Simple Explanation)

### Problem
Many teams already have old security findings in existing code.
If CI fails on all old findings, adoption becomes painful.

### Baseline mode solution
- First, create a baseline of current findings.
- Later scans compare with baseline.
- Old findings = marked as existing/baselined.
- New findings = marked as new.

### Why this helps
- Team can start security now without blocking all delivery.
- CI can fail only for new issues, preventing security regression.

---

## Suppressions (Governed Exceptions)

### What suppression means
Sometimes a finding is a false positive or accepted temporary risk.
Suppression allows marking it as exception.

### Why "governed" matters
Good suppressions must include:

- reason (why this is suppressed)
- expiry date (not forever)
- optional scope (tool/rule/path/fingerprint)

### Simple example
"This finding is in example/demo code only, suppress for 60 days while migration is in progress."

### Why this is important
- Avoids ignoring findings forever.
- Keeps accountability and audit trail.
- Makes security exceptions controlled, not hidden.

---

## In one line

`secagent` combines these tools so teams get broad security coverage, cleaner workflow, safer CI decisions, and practical adoption through baseline + governed suppressions.
