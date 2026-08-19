from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from uuid import UUID

from app.services.connection_manager import manager
from app.services.job_service import job_service

router = APIRouter()

@router.websocket("/ws/jobs/{job_id}")
async def websocket_job_updates(websocket: WebSocket, job_id: UUID):
    """
    WebSocket endpoint for real-time job updates.
    """
    job_id_str = str(job_id)

    # Check if job exists
    job = job_service.get_job(job_id)
    if not job:
        await websocket.accept()
        await websocket.send_json({
            "type": "error",
            "job_id": job_id_str,
            "message": "Job not found"
        })
        await websocket.close(code=4004)
        return

    await manager.connect(job_id_str, websocket)

    try:
        # Send connection confirmation + current job state
        await websocket.send_json({
            "type": "connected",
            "job_id": job_id_str,
            "status": job.status.value if hasattr(job.status, "value") else str(job.status),
            "message": "Connected to job updates",
            "findings_count": len(job.findings),
            "engine": job.engine.value if hasattr(job.engine, "value") else str(job.engine)
        })

        # Keep connection alive and handle client messages
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_json({
                    "type": "pong",
                    "job_id": job_id_str
                })
            elif data == "get_status":
                # Allow client to request current status
                current_job = job_service.get_job(job_id)
                if current_job:
                    await websocket.send_json({
                        "type": "status",
                        "job_id": job_id_str,
                        "status": current_job.status.value if hasattr(current_job.status, "value") else str(current_job.status),
                        "findings_count": len(current_job.findings),
                        "message": "Current job status"
                    })

    except WebSocketDisconnect:
        manager.disconnect(job_id_str, websocket)
    except Exception:
        manager.disconnect(job_id_str, websocket)