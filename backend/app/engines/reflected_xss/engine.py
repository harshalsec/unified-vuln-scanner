import asyncio
import logging
import html
from typing import List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.engines.base import ScanEngine
from app.schemas.domain import EngineResult, EngineType, Finding, Job, Severity
from app.engines.reflected_xss.payloads import XSS_PAYLOADS
from app.engines.reflected_xss.ai_payloads import get_smart_payloads

logger = logging.getLogger("ReflectedXSSEngine")
logging.basicConfig(level=logging.INFO)

class ReflectedXSSEngine(ScanEngine):
    """
    Reflected XSS Engine with encoding detection for better accuracy.
    """

    def __init__(self, job: Job):
        super().__init__(job)
        self.timeout = 8
        self.concurrency = 5

        depth = job.options.get("depth", "normal")
        if depth == "fast":
            self.max_payloads_per_param = 6
        elif depth == "deep":
            self.max_payloads_per_param = 15
        else:
            self.max_payloads_per_param = 10

    @property
    def engine_type(self) -> EngineType:
        return EngineType.REFLECTED_XSS

    async def run(self) -> EngineResult:
        start_time = asyncio.get_event_loop().time()
        findings: List[Finding] = []

        try:
            target = str(self.job.target)
            logger.info(f"[{self.job_id}] Starting Reflected XSS scan on {target}")

            params = self._extract_parameters(target)
            if not params:
                params = ["q", "search", "id", "query"]

            # Use AI-assisted payloads when enabled
            use_ai = self.job.options.get("use_ai_payloads", True)

            if use_ai:
                depth = self.job.options.get("depth", "normal")
                payloads = get_smart_payloads(depth=depth)
                logger.info(f"[{self.job_id}] Using AI-assisted payloads ({len(payloads)} generated)")
            else:
                payloads = XSS_PAYLOADS[:self.max_payloads_per_param]

            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
            ) as client:

                for param in params:
                    tasks = [
                        self._test_payload(client, target, param, payload)
                        for payload in payloads
                    ]

                    results = await self._run_with_concurrency(tasks, self.concurrency)

                    for finding in results:
                        if finding:
                            findings.append(finding)
                            break

            duration = asyncio.get_event_loop().time() - start_time
            logger.info(f"[{self.job_id}] Completed in {duration:.2f}s with {len(findings)} finding(s)")

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
    ) -> Optional[Finding]:
        try:
            test_url = self._build_test_url(base_url, param, payload)
            response = await client.get(test_url)
            body = response.text

            # Check reflection (raw + encoded)
            is_reflected, is_encoded = self._check_reflection(body, payload)

            if not is_reflected:
                return None

            context, confidence = self._analyze_reflection(body, payload, is_encoded)
            severity = self._get_severity(context, confidence, is_encoded)

            return self.create_finding(
                title=f"Possible Reflected XSS in parameter '{param}'",
                description=(
                    f"The payload was reflected in the response.\n\n"
                    f"**Parameter:** `{param}`\n"
                    f"**Payload:** `{payload}`\n"
                    f"**Encoded:** {'Yes' if is_encoded else 'No'}\n"
                    f"**Context:** {context}\n"
                    f"**Confidence:** {confidence}"
                ),
                severity=severity,
                evidence={
                    "parameter": param,
                    "payload": payload,
                    "is_encoded": is_encoded,
                    "context": context,
                    "confidence": confidence,
                    "test_url": test_url,
                    "status_code": response.status_code,
                    "reflected": True,
                },
                remediation=(
                    "Use context-aware output encoding. "
                    "Never reflect user input directly into HTML or JavaScript without proper sanitization."
                ),
                affected_url=test_url,
            )

        except Exception:
            return None

    def _check_reflection(self, body: str, payload: str) -> Tuple[bool, bool]:
        """
        Returns (is_reflected, is_encoded)
        """
        encoded_payload = html.escape(payload)

        if payload in body:
            return True, False          # Raw reflection (dangerous)
        if encoded_payload in body:
            return True, True           # HTML encoded reflection
        return False, False

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
            parsed.fragment
        ))

    def _analyze_reflection(self, body: str, payload: str, is_encoded: bool) -> Tuple[str, str]:
        if is_encoded:
            return "HTML Encoded Reflection", "Low"

        lower_body = body.lower()
        lower_payload = payload.lower()

        if f"<script>{lower_payload}" in lower_body or f"{lower_payload}</script>" in lower_body:
            return "Inside <script> tag", "High"

        if any(evt in lower_body for evt in ["onerror=", "onload=", "onmouseover=", "onfocus=", "ontoggle="]):
            return "Inside HTML event handler", "High"

        if f"src={lower_payload}" in lower_body or f"href={lower_payload}" in lower_body:
            return "Inside HTML attribute", "Medium"

        return "Raw reflection in HTML body", "Medium"

    def _get_severity(self, context: str, confidence: str, is_encoded: bool) -> Severity:
        if is_encoded:
            return Severity.LOW

        if confidence == "High":
            return Severity.HIGH
        if confidence == "Medium":
            return Severity.MEDIUM
        return Severity.LOW