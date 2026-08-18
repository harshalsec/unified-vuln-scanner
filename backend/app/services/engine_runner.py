from app.engines import SubdomainTakeoverEngine, ReflectedXSSEngine
from app.schemas.domain import EngineResult, EngineType, Job
from app.services.job_service import job_service

async def run_engine_for_job(job: Job) -> EngineResult:
    """
    Select the correct engine based on job.engine and execute it.
    """
    job_service.update_job_status(job.id, job.status.RUNNING)

    if job.engine == EngineType.SUBDOMAIN_TAKEOVER:
        engine = SubdomainTakeoverEngine(job)
        result = await engine.run()

    elif job.engine == EngineType.REFLECTED_XSS:
        engine = ReflectedXSSEngine(job)
        result = await engine.run()

    else:
        result = EngineResult(
            job_id=job.id,
            success=False,
            findings=[],
            error=f"Engine '{job.engine}' is not implemented yet",
            duration_seconds=0,
        )

    job_service.add_findings(job.id, result)
    return result