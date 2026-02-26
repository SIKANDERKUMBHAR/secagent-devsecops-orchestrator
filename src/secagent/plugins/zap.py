"""OWASP ZAP DAST plugin using sidecar API mode."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from secagent.config.models import AppConfig
from secagent.core.fingerprint import generate_fingerprint
from secagent.core.models import Finding, ScannerRun
from secagent.core.normalize import normalize_severity
from secagent.plugins.base import ScanContext, ScannerPlugin


class ZapPlugin(ScannerPlugin):
    name = "zap"
    scanner_type = "dast"
    category = "runtime"

    def is_enabled(self, config: AppConfig) -> bool:
        return config.scanners.zap and config.zap.enabled

    def build_command(self, context: ScanContext) -> list[str]:
        return ["zap-api", context.config.zap.api_url, context.config.zap.target_url]

    def parse(self, raw_output: str) -> list[dict[str, Any]]:
        data = json.loads(raw_output or "{}")
        return data.get("alerts", [])

    def normalize(self, parsed_findings: list[dict[str, Any]], include_raw: bool = False) -> list[Finding]:
        findings: list[Finding] = []
        for idx, item in enumerate(parsed_findings):
            refs_raw = (item.get("reference") or "").strip()
            refs = [line.strip() for line in refs_raw.splitlines() if line.strip()]
            cwe = item.get("cweid")
            wasc = item.get("wascid")
            finding = Finding(
                id=f"zap-{idx}",
                fingerprint="",
                tool=self.name,
                scanner_type=self.scanner_type,
                category=self.category,
                title=item.get("name") or item.get("alert") or "ZAP finding",
                description=item.get("description", ""),
                severity=_zap_severity(item),
                confidence=(item.get("confidence") or "").upper() or None,
                resource=item.get("url"),
                file_path=None,
                cwe_ids=[f"CWE-{cwe}"] if cwe and str(cwe) not in {"0", "-1"} else [],
                owasp_categories=[str(wasc)] if wasc and str(wasc) not in {"0", "-1"} else [],
                references=refs,
                remediation=item.get("solution", ""),
                evidence={"evidence": item.get("evidence", "")},
                raw=item if include_raw else None,
                metadata={"rule_id": item.get("pluginId") or item.get("alertRef") or ""},
            )
            finding.fingerprint = generate_fingerprint(finding)
            findings.append(finding)
        return findings

    def timeout_seconds(self, config: AppConfig) -> int:
        return config.zap.timeout_seconds

    def required_binaries(self, config: AppConfig) -> list[str]:
        return []

    def run(self, context: ScanContext) -> tuple[ScannerRun, list[Finding], bool] | None:
        start = time.monotonic()
        try:
            target_url = context.config.zap.target_url
            api_url = context.config.zap.api_url.rstrip("/")
            timeout = self.timeout_seconds(context.config)
            request_timeout = context.config.zap.api_request_timeout_seconds
            api_retries = context.config.zap.api_retries
            retry_delay = context.config.zap.api_retry_delay_seconds
            apikey = _resolve_api_key(context.config)

            self._wait_until_ready(api_url, timeout, apikey, request_timeout)
            scan_id = self._start_spider(api_url, target_url, apikey, request_timeout, api_retries, retry_delay)
            self._wait_spider(api_url, scan_id, timeout, apikey, request_timeout, api_retries, retry_delay)
            self._wait_passive(api_url, timeout, apikey, request_timeout, api_retries, retry_delay)
            alerts = self._collect_alerts(api_url, target_url, apikey, request_timeout, api_retries, retry_delay)
            findings = self.normalize(alerts, include_raw=context.config.report.include_raw)

            return (
                ScannerRun(
                    scanner=self.name,
                    status="ok",
                    duration_seconds=time.monotonic() - start,
                    command=f"zap-api {api_url} {target_url}",
                    return_code=0,
                ),
                findings,
                False,
            )
        except Exception as exc:
            return (
                ScannerRun(
                    scanner=self.name,
                    status="error",
                    duration_seconds=time.monotonic() - start,
                    command="",
                    errors=[str(exc)],
                    return_code=2,
                ),
                [],
                True,
            )

    def _wait_until_ready(
        self,
        api_url: str,
        timeout_seconds: int,
        apikey: str | None,
        request_timeout_seconds: int,
    ) -> None:
        deadline = time.monotonic() + min(timeout_seconds, 60)
        while time.monotonic() < deadline:
            try:
                _api_get_json(
                    f"{api_url}/JSON/core/view/version/",
                    {},
                    apikey,
                    request_timeout_seconds=request_timeout_seconds,
                    retries=0,
                    retry_delay_seconds=0.0,
                )
                return
            except RuntimeError:
                time.sleep(1.0)
        raise TimeoutError("ZAP API did not become ready before timeout")

    def _start_spider(
        self,
        api_url: str,
        target_url: str,
        apikey: str | None,
        request_timeout_seconds: int,
        retries: int,
        retry_delay_seconds: float,
    ) -> str:
        payload = _api_get_json(
            f"{api_url}/JSON/spider/action/scan/",
            {"url": target_url, "recurse": "true"},
            apikey,
            request_timeout_seconds=request_timeout_seconds,
            retries=retries,
            retry_delay_seconds=retry_delay_seconds,
        )
        scan = payload.get("scan")
        if not scan:
            raise ValueError("ZAP spider did not return a scan id")
        return str(scan)

    def _wait_spider(
        self,
        api_url: str,
        scan_id: str,
        timeout_seconds: int,
        apikey: str | None,
        request_timeout_seconds: int,
        retries: int,
        retry_delay_seconds: float,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            payload = _api_get_json(
                f"{api_url}/JSON/spider/view/status/",
                {"scanId": scan_id},
                apikey,
                request_timeout_seconds=request_timeout_seconds,
                retries=retries,
                retry_delay_seconds=retry_delay_seconds,
            )
            progress = int(payload.get("status", "0"))
            if progress >= 100:
                return
            time.sleep(1.0)
        raise TimeoutError("ZAP spider timed out")

    def _wait_passive(
        self,
        api_url: str,
        timeout_seconds: int,
        apikey: str | None,
        request_timeout_seconds: int,
        retries: int,
        retry_delay_seconds: float,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            payload = _api_get_json(
                f"{api_url}/JSON/pscan/view/recordsToScan/",
                {},
                apikey,
                request_timeout_seconds=request_timeout_seconds,
                retries=retries,
                retry_delay_seconds=retry_delay_seconds,
            )
            left = int(payload.get("recordsToScan", "0"))
            if left <= 0:
                return
            time.sleep(1.0)
        raise TimeoutError("ZAP passive scan timed out")

    def _collect_alerts(
        self,
        api_url: str,
        target_url: str,
        apikey: str | None,
        request_timeout_seconds: int,
        retries: int,
        retry_delay_seconds: float,
    ) -> list[dict[str, Any]]:
        start_at = 0
        count = 500
        alerts: list[dict[str, Any]] = []
        while True:
            payload = _api_get_json(
                f"{api_url}/JSON/core/view/alerts/",
                {"baseurl": target_url, "start": str(start_at), "count": str(count)},
                apikey,
                request_timeout_seconds=request_timeout_seconds,
                retries=retries,
                retry_delay_seconds=retry_delay_seconds,
            )
            page = payload.get("alerts", [])
            if not page:
                break
            alerts.extend(page)
            if len(page) < count:
                break
            start_at += count
        return alerts


def _resolve_api_key(config: AppConfig) -> str | None:
    if not config.zap.api_key_env:
        return None
    return os.getenv(config.zap.api_key_env)


def _api_get_json(
    url: str,
    params: dict[str, str],
    apikey: str | None,
    request_timeout_seconds: int = 20,
    retries: int = 3,
    retry_delay_seconds: float = 1.0,
) -> dict[str, Any]:
    payload = dict(params)
    if apikey:
        payload["apikey"] = apikey
    query = urllib.parse.urlencode(payload)
    request_url = f"{url}?{query}" if query else url

    attempt = 0
    while True:
        try:
            with urllib.request.urlopen(request_url, timeout=request_timeout_seconds) as response:  # noqa: S310
                body = response.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            if _should_retry_status(exc.code) and attempt < retries:
                attempt += 1
                time.sleep(retry_delay_seconds)
                continue
            raise RuntimeError(f"ZAP API request failed ({exc.code}) for {request_url}") from exc
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt < retries:
                attempt += 1
                time.sleep(retry_delay_seconds)
                continue
            raise RuntimeError(f"ZAP API request failed for {request_url}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"ZAP API returned invalid JSON for {request_url}") from exc


def _should_retry_status(status_code: int) -> bool:
    return status_code in {429, 500, 502, 503, 504}


def _zap_severity(item: dict[str, Any]):
    risk = (item.get("risk") or "").strip().lower()
    risk_code = str(item.get("riskcode", "")).strip()
    if risk in {"high"} or risk_code == "3":
        return normalize_severity("high")
    if risk in {"medium"} or risk_code == "2":
        return normalize_severity("medium")
    if risk in {"low"} or risk_code == "1":
        return normalize_severity("low")
    if risk in {"informational", "info"} or risk_code == "0":
        return normalize_severity("info")
    return normalize_severity(None)
