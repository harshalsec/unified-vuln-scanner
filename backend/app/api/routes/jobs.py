from typing import List
from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.schemas.domain import Job, JobCreate, JobStatus
from app.services.job_service import job_service

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