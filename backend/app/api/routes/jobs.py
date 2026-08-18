from typing import List
from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.schemas.domain import Job, JobCreate, JobStatus, EngineResult
from app.services.job_service import job_service
from app.services.engine_runner import run_engine_for_job

router = APIRouter(prefix="/jobs", tags=["Jobs"])

@router.post("/", response_model=Job, status_code=status.HTTP_201_CREATED)
async def create_job(job_create: JobCreate):
    """
    Create a new vulnerability scan job.
    """
    job = job_service.create_job(job_create)
    return job

@router.get("/", response_model=List[Job])
async def list_jobs():
    """
    List all jobs (newest first).
    """
    return job_service.list_jobs()

@router.get("/{job_id}", response_model=Job)
async def get_job(job_id: UUID):
    """
    Get a specific job by ID.
    """
    job = job_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found",
        )
    return job

from app.services.engine_runner import run_engine_for_job
from app.schemas.domain import EngineResult

@router.post("/{job_id}/run", response_model=EngineResult)
async def run_job(job_id: UUID):
    """
    Manually trigger the scanning engine for an existing job.
    """
    job = job_service.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.status == JobStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Job is already running")

    result = await run_engine_for_job(job)
    return result

