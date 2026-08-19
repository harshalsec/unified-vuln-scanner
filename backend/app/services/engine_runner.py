import asyncio
from app.engines import SubdomainTakeoverEngine, ReflectedXSSEngine, BOLAEngine
from app.schemas.domain import EngineResult, EngineType, Job, JobStatus
from app.services.job_service import job_service
from app.services.connection_manager import manager

async def run_engine_for_job(job: Job) -> EngineResult:
    """
    Run the correct engine and stream live progress via WebSocket.
    """
    job_id_str = str(job.id)

    # Mark as running
    job_service.update_job_status(job.id, JobStatus.RUNNING)

    await manager.send_message(job_id_str, {
        "type": "status",
        "job_id": job_id_str,
        "status": "running",
        "message": f"Starting {job.engine.value} engine..."
    })

    # Select engine
    if job.engine == EngineType.SUBDOMAIN_TAKEOVER:
        engine = SubdomainTakeoverEngine(job)
    elif job.engine == EngineType.REFLECTED_XSS:
        engine = ReflectedXSSEngine(job)
    elif job.engine == EngineType.BOLA:
        engine = BOLAEngine(job)
    else:
        result = EngineResult(
            job_id=job.id,
            success=False,
            findings=[],
            error=f"Engine '{job.engine}' is not implemented yet",
            duration_seconds=0,
        )
        await _send_final_update(job_id_str, result)
        job_service.add_findings(job.id, result)
        return result

    # Create a reliable progress sender
    async def send_progress(percentage: float, message: str):
        await manager.send_message(job_id_str, {
            "type": "progress",
            "job_id": job_id_str,
            "percentage": round(percentage, 1),
            "message": message
        })

    # Override emit_progress so every engine automatically streams
    async def emit_with_ws(percentage: float, message: str):
        await send_progress(percentage, message)
        return await ScanEngine.emit_progress(engine, percentage, message)

    # Import here to avoid circular issues
    from app.engines.base import ScanEngine
    engine.emit_progress = emit_with_ws

    # Send an initial progress message
    await send_progress(1, "Engine initialized")

    # Run the engine
    result = await engine.run()

    # Save results
    job_service.add_findings(job.id, result)

    # Final update
    await _send_final_update(job_id_str, result)

    return result

async def _send_final_update(job_id_str: str, result: EngineResult):
    await manager.send_message(job_id_str, {
        "type": "completed" if result.success else "failed",
        "job_id": job_id_str,
        "success": result.success,
        "findings_count": len(result.findings),
        "findings": [f.model_dump(mode="json") for f in result.findings],
        "error": result.error,
        "duration_seconds": result.duration_seconds,
        "message": "Scan completed successfully" if result.success else "Scan failed"
    })