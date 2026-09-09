import asyncio
import logging
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.engines.base import ScanEngine
from app.schemas.domain import EngineResult, EngineType, Finding, Job, Severity
from app.engines.sql_injection.payloads import SQLI_PAYLOADS

logger = logging.getLogger("SQLInjectionEngine")
logging.basicConfig(level=logging.INFO)

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "mysqli_",
    "pg_query",
    "syntax error at or near",
    "ora-01756",
    "ora-00933",
    "sqlite3.operationalerror",
    "microsoft ole db",
    "odbc sql server driver",
    "postgresql query failed",
    "sql command not properly ended",
    "check the manual that corresponds to your mysql",
    "mariadb",
    "syntax error near",
]

class SQLInjectionEngine(ScanEngine):
    """
    Fast educational SQL Injection detection engine.
    """

    def __init__(self, job: Job):
        super().__init__(job)
        self.timeout = 8
        self.max_payloads = 6
        self.concurrency = 4

    @property
    def engine_type(self) -> EngineType:
        return EngineType.SQL_INJECTION

    async def run(self) -> EngineResult:
        start_time = asyncio.get_event_loop().time()
        findings: List[Finding] = []

        try:
            target = str(self.job.target)
            logger.info(f"[{self.job_id}] Starting fast SQL Injection scan on {target}")

            params = self._extract_parameters(target)
            if not params:
                params = ["id", "q", "search"]

            payloads = SQLI_PAYLOADS[: self.max_payloads]

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
            ) as client:

                # Baseline
                baseline_resp = await client.get(target)
                baseline_body = baseline_resp.text.lower()
                baseline_len = len(baseline_resp.content)
                baseline_status = baseline_resp.status_code

                total = max(len(params) * len(payloads), 1)
                current = 0

                for param in params:
                    # Create concurrent tasks for this parameter
                    tasks = []
                    for payload in payloads:
                        current += 1
                        tasks.append(
                            self._test_payload(
                                client,
                                target,
                                param,
                                payload,
                                baseline_body,
                                baseline_len,
                                baseline_status,
                            )
                        )

                    # Run with limited concurrency
                    results = await self._run_with_concurrency(tasks, self.concurrency)

                    for finding in results:
                        if finding:
                            findings.append(finding)
                            break  # stop after first finding on this param

                    # Progress update
                    percentage = round((current / total) * 100, 1)
                    await self.emit_progress(percentage, f"Finished testing '{param}'")

            duration = asyncio.get_event_loop().time() - start_time
            logger.info(
                f"[{self.job_id}] Fast SQLi scan completed in {duration:.2f}s - {len(findings)} finding(s)"
            )

            return EngineResult(
                job_id=self.job_id,
                success=True,
                findings=findings,
                error=None,
                duration_seconds=round(duration, 2),
            )

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            logger.error(f"[{self.job_id}] Error: {str(e)}")
            return EngineResult(
                job_id=self.job_id,
                success=False,
                findings=findings,
                error=str(e),
                duration_seconds=round(duration, 2),
            )

    async def _run_with_concurrency(self, tasks: List, limit: int):
        semaphore = asyncio.Semaphore(limit)

        async def sem_task(task):
            async with semaphore:
                return await task

        return await asyncio.gather(*(sem_task(t) for t in tasks))

    def _extract_parameters(self, url: str) -> List[str]:
        try:
            parsed = urlparse(url)
            return list(parse_qs(parsed.query).keys())
        except Exception:
            return []

    async def _test_payload(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        param: str,
        payload: str,
        baseline_body: str,
        baseline_len: int,
        baseline_status: int,
    ) -> Optional[Finding]:
        try:
            test_url = self._build_test_url(base_url, param, payload)
            response = await client.get(test_url)

            body = response.text.lower()
            body_len = len(response.content)
            status = response.status_code

            # 1. Error-based
            for signature in SQL_ERROR_SIGNATURES:
                if signature in body and signature not in baseline_body:
                    return self.create_finding(
                        title=f"Possible SQL Injection (Error-based) in '{param}'",
                        description=(
                            f"Database error signature detected after injecting payload "
                            f"into `{param}`.\n\n"
                            f"**Payload:** `{payload}`\n"
                            f"**Signature:** `{signature}`"
                        ),
                        severity=Severity.HIGH,
                        evidence={
                            "parameter": param,
                            "payload": payload,
                            "detection_type": "error-based",
                            "matched_signature": signature,
                            "test_url": test_url,
                            "status_code": status,
                        },
                        remediation="Use parameterized queries / prepared statements.",
                        affected_url=test_url,
                    )

            # 2. Boolean / content difference
            length_diff = abs(body_len - baseline_len)
            if length_diff > 150 or (status != baseline_status and status >= 500):
                return self.create_finding(
                    title=f"Possible SQL Injection (Content Diff) in '{param}'",
                    description=(
                        f"Response changed significantly after payload injection.\n\n"
                        f"**Payload:** `{payload}`\n"
                        f"**Length change:** {baseline_len} → {body_len}"
                    ),
                    severity=Severity.MEDIUM,
                    evidence={
                        "parameter": param,
                        "payload": payload,
                        "detection_type": "boolean-content",
                        "baseline_length": baseline_len,
                        "response_length": body_len,
                        "test_url": test_url,
                        "status_code": status,
                    },
                    remediation="Use parameterized queries and input validation.",
                    affected_url=test_url,
                )

        except Exception:
            return None

        return None

    def _build_test_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        query_dict = parse_qs(parsed.query)
        query_dict[param] = [payload]
        new_query = urlencode(query_dict, doseq=True)

        return urlunparse((
            parsed.scheme or "https",
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            new_query,
            parsed.fragment,
        ))