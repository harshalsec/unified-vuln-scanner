from datetime import datetime
from typing import Dict, Optional
from uuid import UUID, uuid4

from app.schemas.domain import (
    EngineResult,
    EngineType,
    Job,
    JobCreate,
    JobStatus,
    ProgressEvent,
)

class JobService:
    """
    Simple in-memory Job orchestration service.
    Later we will replace the in-memory store with a real database.
    """

    def __init__(self):
        self._jobs: Dict[UUID, Job] = {}

    def create_job(self, job_create: JobCreate) -> Job:
        """Create a new job and store it."""
        job = Job(
            id=uuid4(),
            engine=job_create.engine,
            status=JobStatus.PENDING,
            target=job_create.target,
            additional_targets=job_create.additional_targets,
            identity_pair=job_create.identity_pair,
            options=job_create.options,
            timeout_seconds=job_create.timeout_seconds,
            created_at=datetime.utcnow(),
        )
        self._jobs[job.id] = job
        return job

    def get_job(self, job_id: UUID) -> Optional[Job]:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[Job]:
        """Return all jobs (newest first)."""
        return sorted(
            self._jobs.values(),
            key=lambda j: j.created_at,
            reverse=True,
        )

    def update_job_status(
        self,
        job_id: UUID,
        status: JobStatus,
        error_message: Optional[str] = None,
    ) -> Optional[Job]:
        """Update the status of a job."""
        job = self._jobs.get(job_id)
        if not job:
            return None

        job.status = status

        if status == JobStatus.RUNNING and job.started_at is None:
            job.started_at = datetime.utcnow()

        if status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
            job.finished_at = datetime.utcnow()

        if error_message:
            job.error_message = error_message

        self._jobs[job_id] = job
        return job

    def add_findings(self, job_id: UUID, result: EngineResult) -> Optional[Job]:
        """Attach findings from an engine result to the job."""
        job = self._jobs.get(job_id)
        if not job:
            return None

        job.findings = result.findings
        job.status = JobStatus.COMPLETED if result.success else JobStatus.FAILED
        job.finished_at = datetime.utcnow()

        if not result.success and result.error:
            job.error_message = result.error

        self._jobs[job_id] = job
        return job

# Create a single shared instance (simple singleton for now)
job_service = JobService()