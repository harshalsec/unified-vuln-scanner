import asyncio
import logging
from typing import List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from app.engines.base import ScanEngine
from app.schemas.domain import EngineResult, EngineType, Finding, Job, Severity

logger = logging.getLogger("OpenRedirectEngine")
logging.basicConfig(level=logging.INFO)

# Common parameter names that often cause open redirects
REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "return",
    "returnTo", "return_to", "continue", "dest", "destination", "go",
    "goto", "target", "rurl", "redirect_to", "out", "view", "login"
]

# Test destination (harmless external domain)
TEST_REDIRECT_TARGET = "https://example.com/open-redirect-test"

class OpenRedirectEngine(ScanEngine):
    """
    Detects Open Redirect vulnerabilities.
    """

    def __init__(self, job: Job):
        super().__init__(job)
        self.timeout = min(job.timeout_seconds or 12, 15)

    @property
    def engine_type(self) -> EngineType:
        return EngineType.OPEN_REDIRECT

    async def run(self) -> EngineResult:
        start_time = asyncio.get_event_loop().time()
        findings: List[Finding] = []

        try:
            target = str(self.job.target)
            logger.info(f"[{self.job_id}] Starting Open Redirect scan on {target}")

            params_to_test = self._get_params_to_test(target)

            await self.emit_progress(5, f"Testing {len(params_to_test)} parameter(s)")

            async with httpx.AsyncClient(
                follow_redirects=False,  # Important: do not follow redirects
                timeout=self.timeout,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"},
            ) as client:

                total = len(params_to_test)
                for index, param in enumerate(params_to_test):
                    percentage = round(((index + 1) / total) * 100, 1)
                    await self.emit_progress(percentage, f"Testing parameter: {param}")

                    finding = await self._test_param(client, target, param)
                    if finding:
                        findings.append(finding)

            duration = asyncio.get_event_loop().time() - start_time
            logger.info(f"[{self.job_id}] Open Redirect scan finished - {len(findings)} finding(s)")

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

    def _get_params_to_test(self, url: str) -> List[str]:
        """Get existing parameters + common redirect parameter names."""
        try:
            parsed = urlparse(url)
            existing = list(parse_qs(parsed.query).keys())
        except Exception:
            existing = []

        # Combine existing + common names (unique)
        combined = list(dict.fromkeys(existing + REDIRECT_PARAMS))
        return combined[:12]  # limit for speed

    async def _test_param(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        param: str,
    ) -> Optional[Finding]:
        try:
            test_url = self._build_test_url(base_url, param, TEST_REDIRECT_TARGET)
            response = await client.get(test_url)

            location = response.headers.get("location", "")

            # Check if the response redirects to our external test domain
            if response.status_code in (301, 302, 303, 307, 308):
                if "example.com" in location.lower():
                    return self.create_finding(
                        title=f"Possible Open Redirect in parameter '{param}'",
                        description=(
                            f"The application redirects to an external domain when the "
                            f"`{param}` parameter is controlled by the user.\n\n"
                            f"**Redirect Location:** `{location}`"
                        ),
                        severity=Severity.MEDIUM,
                        evidence={
                            "parameter": param,
                            "test_url": test_url,
                            "status_code": response.status_code,
                            "location_header": location,
                        },
                        remediation=(
                            "Do not redirect to user-controlled URLs. "
                            "Use a whitelist of allowed redirect destinations."
                        ),
                        affected_url=test_url,
                    )
        except Exception:
            pass

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
            parsed.fragment
        ))