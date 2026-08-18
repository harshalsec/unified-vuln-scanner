import asyncio
import logging
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from dns import resolver

from app.engines.base import ScanEngine
from app.schemas.domain import EngineResult, EngineType, Finding, Job, Severity
from app.engines.subdomain_takeover.fingerprints import VULNERABLE_FINGERPRINTS

# Simple logger for development
logger = logging.getLogger("SubdomainTakeoverEngine")
logging.basicConfig(level=logging.INFO)

class SubdomainTakeoverEngine(ScanEngine):
    """
    Detects potential Subdomain Takeover vulnerabilities.
    Supports multiple subdomains via job.options["subdomains"].
    """

    def __init__(self, job: Job):
        super().__init__(job)
        self.timeout = min(job.timeout_seconds or 15, 20)

    @property
    def engine_type(self) -> EngineType:
        return EngineType.SUBDOMAIN_TAKEOVER

    async def run(self) -> EngineResult:
        start_time = asyncio.get_event_loop().time()
        findings: List[Finding] = []

        try:
            domains = self._collect_domains()
            logger.info(f"[{self.job_id}] Starting scan for {len(domains)} domain(s)")

            if not domains:
                return EngineResult(
                    job_id=self.job_id,
                    success=False,
                    findings=[],
                    error="No valid domains provided",
                    duration_seconds=0,
                )

            total = len(domains)

            for index, domain in enumerate(domains):
                percentage = round(((index + 1) / total) * 100, 1)
                message = f"Checking domain: {domain}"
                await self.emit_progress(percentage, message)
                logger.info(f"[{self.job_id}] {message}")

                domain_findings = await self._check_domain(domain)
                findings.extend(domain_findings)

            duration = asyncio.get_event_loop().time() - start_time
            logger.info(f"[{self.job_id}] Scan completed in {duration:.2f}s with {len(findings)} finding(s)")

            return EngineResult(
                job_id=self.job_id,
                success=True,
                findings=findings,
                error=None,
                duration_seconds=round(duration, 2),
            )

        except Exception as e:
            duration = asyncio.get_event_loop().time() - start_time
            logger.error(f"[{self.job_id}] Engine error: {str(e)}")
            return EngineResult(
                job_id=self.job_id,
                success=False,
                findings=findings,
                error=str(e),
                duration_seconds=round(duration, 2),
            )

    def _collect_domains(self) -> List[str]:
        """Collect domains from target + additional_targets + options.subdomains"""
        domains = []

        # From main target
        domains.extend(self._extract_domains([str(self.job.target)]))

        # From additional_targets
        domains.extend(self._extract_domains([str(t) for t in self.job.additional_targets]))

        # From options.subdomains (new feature)
        extra_subdomains = self.job.options.get("subdomains", [])
        if isinstance(extra_subdomains, list):
            domains.extend(self._extract_domains(extra_subdomains))

        # Remove duplicates and empty values
        clean_domains = list(set(d for d in domains if d))
        return clean_domains

    def _extract_domains(self, targets: List[str]) -> List[str]:
        domains = []
        for target in targets:
            try:
                if "://" not in target:
                    target = "http://" + target
                parsed = urlparse(target)
                host = parsed.hostname
                if host:
                    domains.append(host.lower().strip("."))
            except Exception:
                continue
        return domains

    async def _check_domain(self, domain: str) -> List[Finding]:
        findings = []

        cname = await self._get_cname(domain)
        if not cname:
            logger.debug(f"[{self.job_id}] No CNAME found for {domain}")
            return findings

        logger.info(f"[{self.job_id}] CNAME found: {domain} → {cname}")

        # 1. Check dangling (NXDOMAIN)
        is_dangling = await self._is_nxdomain(cname)
        if is_dangling:
            findings.append(
                self.create_finding(
                    title=f"Dangling CNAME Detected on {domain}",
                    description=(
                        f"The domain `{domain}` has a CNAME pointing to `{cname}`, "
                        f"but `{cname}` does not resolve (NXDOMAIN). "
                        f"This is a strong indicator of a potential subdomain takeover."
                    ),
                    severity=Severity.HIGH,
                    evidence={
                        "domain": domain,
                        "cname": cname,
                        "reason": "CNAME target returns NXDOMAIN",
                    },
                    remediation=f"Remove the DNS CNAME record for `{domain}` or claim the resource at `{cname}`.",
                    affected_url=f"http://{domain}",
                )
            )
            return findings

        # 2. Check fingerprints
        is_vulnerable, service, fingerprint = await self._check_fingerprints(cname)

        if is_vulnerable:
            severity = self._get_severity_for_service(service)
            findings.append(
                self.create_finding(
                    title=f"Potential Subdomain Takeover on {domain}",
                    description=(
                        f"The domain `{domain}` has a CNAME pointing to `{cname}`. "
                        f"The response matches a known fingerprint of **{service}**."
                    ),
                    severity=severity,
                    evidence={
                        "domain": domain,
                        "cname": cname,
                        "vulnerable_service": service,
                        "matched_fingerprint": fingerprint,
                    },
                    remediation=(
                        f"1. Remove the DNS CNAME record for `{domain}`, or\n"
                        f"2. Claim the {service} resource that `{cname}` points to."
                    ),
                    affected_url=f"http://{domain}",
                )
            )
        else:
            # 3. Informational finding
            findings.append(
                self.create_finding(
                    title=f"CNAME Found on {domain} (Manual Review Recommended)",
                    description=(
                        f"The domain `{domain}` has a CNAME pointing to `{cname}`. "
                        f"No known vulnerable fingerprint was matched."
                    ),
                    severity=Severity.LOW,
                    evidence={
                        "domain": domain,
                        "cname": cname,
                        "note": "No fingerprint matched - possible unknown service",
                    },
                    remediation="Manually verify whether the CNAME target is still claimed.",
                    affected_url=f"http://{domain}",
                )
            )

        return findings

    async def _get_cname(self, domain: str) -> Optional[str]:
        try:
            answers = resolver.resolve(domain, "CNAME")
            for rdata in answers:
                return str(rdata.target).rstrip(".").lower()
        except Exception:
            return None
        return None

    async def _is_nxdomain(self, domain: str) -> bool:
        try:
            resolver.resolve(domain, "A")
            return False
        except resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    async def _check_fingerprints(self, cname: str) -> Tuple[bool, Optional[str], Optional[str]]:
        headers = {"User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0)"}
        urls = [f"https://{cname}", f"http://{cname}"]

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=self.timeout,
            headers=headers,
            verify=False,
        ) as client:
            for url in urls:
                try:
                    response = await client.get(url)
                    body = response.text.lower()

                    for service, fingerprints in VULNERABLE_FINGERPRINTS.items():
                        for fp in fingerprints:
                            if fp in body:
                                return True, service, fp
                except Exception:
                    continue

        return False, None, None

    def _get_severity_for_service(self, service: str) -> Severity:
        high_risk = ["GitHub Pages", "Heroku", "AWS S3", "Azure", "Netlify", "Shopify"]
        if service in high_risk:
            return Severity.HIGH
        return Severity.MEDIUM