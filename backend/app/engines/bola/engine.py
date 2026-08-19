import asyncio
import logging
from typing import List, Optional

import httpx

from app.engines.base import ScanEngine
from app.engines.bola.helpers import (
    make_request,
    is_success,
    is_unauthorized,
    response_similarity,
)
from app.schemas.domain import EngineResult, EngineType, Finding, Job, Severity

logger = logging.getLogger("BOLAEngine")
logging.basicConfig(level=logging.INFO)

class BOLAEngine(ScanEngine):
    """
    Final improved BOLA/IDOR detection engine.
    """

    def __init__(self, job: Job):
        super().__init__(job)
        self.timeout = min(job.timeout_seconds or 20, 30)

        self.low_token = None
        self.high_token = None

        if job.identity_pair:
            self.low_token = job.identity_pair.low_privilege_token
            self.high_token = job.identity_pair.high_privilege_token

        # Configurable options
        self.methods = job.options.get("methods", ["GET", "PUT", "DELETE"])
        self.auth_header_prefix = job.options.get("auth_header_prefix", "Bearer")
        self.similarity_threshold = float(job.options.get("similarity_threshold", 0.85))
        self.delay = float(job.options.get("delay", 0.3))  # polite delay
        self.custom_headers = job.options.get("headers", {})

    @property
    def engine_type(self) -> EngineType:
        return EngineType.BOLA

    async def run(self) -> EngineResult:
        start_time = asyncio.get_event_loop().time()
        findings: List[Finding] = []

        try:
            if not self.low_token or not self.high_token:
                return EngineResult(
                    job_id=self.job_id,
                    success=False,
                    findings=[],
                    error="identity_pair with low_privilege_token and high_privilege_token is required",
                    duration_seconds=0,
                )

            target = str(self.job.target)
            logger.info(f"[{self.job_id}] Starting final BOLA scan on {target}")

            endpoints = self.job.options.get("endpoints", [])
            object_ids = self.job.options.get("object_ids", [])

            if not endpoints:
                endpoints = [target]

            # If no object_ids provided, still test the endpoints once
            if not object_ids:
                object_ids = [None]

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)",
                    **self.custom_headers,
                },
            ) as client:

                total_tests = len(endpoints) * len(object_ids) * len(self.methods)
                current = 0

                for endpoint in endpoints:
                    for obj_id in object_ids:
                        for method in self.methods:
                            current += 1
                            percentage = round((current / total_tests) * 100, 1)

                            id_display = obj_id if obj_id is not None else "direct"
                            await self.emit_progress(
                                percentage,
                                f"Testing {method} {endpoint} [{id_display}]"
                            )

                            finding = await self._test_object(
                                client, endpoint, obj_id, method
                            )
                            if finding:
                                findings.append(finding)

                            # Polite delay
                            if self.delay > 0:
                                await asyncio.sleep(self.delay)

            duration = asyncio.get_event_loop().time() - start_time
            logger.info(
                f"[{self.job_id}] BOLA scan completed in {duration:.2f}s → {len(findings)} finding(s)"
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

    async def _test_object(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        object_id: Optional[str],
        method: str,
    ) -> Optional[Finding]:
        try:
            url = self._build_url(endpoint, object_id)

            high_resp = await make_request(
                client,
                method,
                url,
                token=self.high_token,
                auth_header_prefix=self.auth_header_prefix,
            )

            low_resp = await make_request(
                client,
                method,
                url,
                token=self.low_token,
                auth_header_prefix=self.auth_header_prefix,
            )

            high_success = is_success(high_resp.status_code)
            low_success = is_success(low_resp.status_code)
            low_forbidden = is_unauthorized(low_resp.status_code)

            similarity = response_similarity(high_resp.content, low_resp.content)

            # Case 1: Clear BOLA
            if high_success and low_success:
                severity = Severity.HIGH
                reason = "Both identities received successful responses"

                if similarity >= self.similarity_threshold:
                    severity = Severity.CRITICAL
                    reason += f" | High response similarity ({similarity:.2f})"

                return self.create_finding(
                    title=f"BOLA/IDOR Detected – {method} {url}",
                    description=(
                        f"Both high-privilege and low-privilege users successfully accessed "
                        f"the resource.\n\n"
                        f"**Method:** `{method}`\n"
                        f"**URL:** `{url}`\n"
                        f"**Similarity:** {similarity:.2f}\n"
                        f"**Reason:** {reason}"
                    ),
                    severity=severity,
                    evidence={
                        "url": url,
                        "method": method,
                        "object_id": object_id,
                        "high_status": high_resp.status_code,
                        "low_status": low_resp.status_code,
                        "high_length": len(high_resp.content),
                        "low_length": len(low_resp.content),
                        "similarity": round(similarity, 3),
                        "reason": reason,
                    },
                    remediation=(
                        "Implement proper object-level authorization checks. "
                        "Verify that the current user is allowed to access the specific object."
                    ),
                    affected_url=url,
                )

            # Case 2: Unusual pattern
            if low_success and not high_success:
                return self.create_finding(
                    title=f"Unusual Access Pattern – {method} {url}",
                    description=(
                        f"Low-privilege user succeeded while high-privilege user failed."
                    ),
                    severity=Severity.MEDIUM,
                    evidence={
                        "url": url,
                        "method": method,
                        "object_id": object_id,
                        "high_status": high_resp.status_code,
                        "low_status": low_resp.status_code,
                        "similarity": round(similarity, 3),
                    },
                    remediation="Review authorization logic for inconsistent behavior.",
                    affected_url=url,
                )

            # Secure case
            if high_success and low_forbidden:
                return None

        except Exception as e:
            logger.debug(f"Error testing {method} {endpoint}: {e}")

        return None

    def _build_url(self, endpoint: str, object_id: Optional[str]) -> str:
        if object_id is None:
            return endpoint

        if "{id}" in endpoint:
            return endpoint.replace("{id}", str(object_id))
        if "{object_id}" in endpoint:
            return endpoint.replace("{object_id}", str(object_id))

        return f"{endpoint.rstrip('/')}/{object_id}"