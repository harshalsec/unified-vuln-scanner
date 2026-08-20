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
    try:
        job = job_service.create_job(job_create)
        return job
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unable to create job. Please check your input.",
        )

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

@router.post("/{job_id}/run", response_model=EngineResult)
async def run_job(job_id: UUID):
    """
    Manually trigger the scanning engine for an existing job.
    """
    job = job_service.get_job(job_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found",
        )

    if job.status == JobStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Job is already running",
        )

    try:
        result = await run_engine_for_job(job)
        return result
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan failed due to an internal error.",
        )