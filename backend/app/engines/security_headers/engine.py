import asyncio
import logging
from typing import List, Dict

import httpx

from app.engines.base import ScanEngine
from app.schemas.domain import EngineResult, EngineType, Finding, Job, Severity

logger = logging.getLogger("SecurityHeadersEngine")
logging.basicConfig(level=logging.INFO)

# Recommended security headers and their severity if missing
SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": Severity.HIGH,
        "description": "HTTP Strict Transport Security (HSTS) is missing. This allows SSL stripping attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    "content-security-policy": {
        "severity": Severity.HIGH,
        "description": "Content Security Policy (CSP) is missing. This increases XSS risk.",
        "remediation": "Implement a strong Content-Security-Policy header."
    },
    "x-frame-options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options header is missing. The site may be vulnerable to Clickjacking.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
    },
    "x-content-type-options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options header is missing. Browser may MIME-sniff responses.",
        "remediation": "Add 'X-Content-Type-Options: nosniff'."
    },
    "referrer-policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy header is missing. Sensitive data may leak via Referer header.",
        "remediation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
    },
    "permissions-policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy header is missing. Browser features are not restricted.",
        "remediation": "Add a Permissions-Policy header to restrict powerful browser features."
    },
}

class SecurityHeadersEngine(ScanEngine):
    """
    Detects missing or weak security headers.
    """

    def __init__(self, job: Job):
        super().__init__(job)
        self.timeout = min(job.timeout_seconds or 15, 20)

    @property
    def engine_type(self) -> EngineType:
        return EngineType.SECURITY_HEADERS

    async def run(self) -> EngineResult:
        start_time = asyncio.get_event_loop().time()
        findings: List[Finding] = []

        try:
            target = str(self.job.target)
            logger.info(f"[{self.job_id}] Starting Security Headers scan on {target}")

            await self.emit_progress(10, "Sending request to target")

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
            ) as client:
                response = await client.get(target)

            await self.emit_progress(50, "Analyzing security headers")

            headers = {k.lower(): v for k, v in response.headers.items()}

            for header_name, info in SECURITY_HEADERS.items():
                if header_name not in headers:
                    findings.append(
                        self.create_finding(
                            title=f"Missing Security Header: {header_name}",
                            description=info["description"],
                            severity=info["severity"],
                            evidence={
                                "missing_header": header_name,
                                "status_code": response.status_code,
                                "url": str(response.url),
                            },
                            remediation=info["remediation"],
                            affected_url=str(response.url),
                        )
                    )

            await self.emit_progress(100, "Header analysis completed")

            duration = asyncio.get_event_loop().time() - start_time
            logger.info(f"[{self.job_id}] Security Headers scan finished - {len(findings)} finding(s)")

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