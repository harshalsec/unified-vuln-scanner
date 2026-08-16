from abc import ABC, abstractmethod
from typing import AsyncGenerator, Optional
from uuid import UUID

from app.schemas.domain import (
    EngineResult,
    EngineType,
    Finding,
    Job,
    ProgressEvent,
)

class ScanEngine(ABC):
    """
    Abstract base class for all vulnerability scanning engines.
    Every engine (BOLA, Subdomain Takeover, Reflected XSS) must inherit from this.
    """

    def __init__(self, job: Job):
        self.job = job
        self.job_id: UUID = job.id

    @property
    @abstractmethod
    def engine_type(self) -> EngineType:
        """Return the type of this engine."""
        pass

    @abstractmethod
    async def run(self) -> EngineResult:
        """
        Main entry point.
        Execute the scan and return a complete EngineResult.
        """
        pass

    async def emit_progress(self, percentage: float, message: str) -> ProgressEvent:
        """
        Helper to create a progress event.
        Later we will send this through WebSocket.
        """
        return ProgressEvent(
            job_id=self.job_id,
            percentage=percentage,
            message=message,
        )

    def create_finding(
        self,
        title: str,
        description: str,
        severity,
        evidence: Optional[dict] = None,
        remediation: Optional[str] = None,
        affected_url: Optional[str] = None,
        cvss=None,
    ) -> Finding:
        """
        Helper to create a standardized Finding object.
        """
        return Finding(
            engine=self.engine_type,
            title=title,
            description=description,
            severity=severity,
            evidence=evidence or {},
            remediation=remediation,
            affected_url=affected_url,
            cvss=cvss,
        )