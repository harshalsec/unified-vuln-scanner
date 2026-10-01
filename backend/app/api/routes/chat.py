from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Any

from app.services.ai_orchestrator import orchestrator

router = APIRouter(prefix="/chat", tags=["AI Chat Scanner"])

class StartScanRequest(BaseModel):
    target: str = Field(..., min_length=3, description="Target URL or domain")

class AnswerRequest(BaseModel):
    session_id: str
    answer: str = Field(..., min_length=1)

class RunScanRequest(BaseModel):
    session_id: str

@router.post("/start")
async def start_scan(payload: StartScanRequest):
    """
    Start a new AI-driven multi-engine scan session.
    """
    result = orchestrator.start_session(payload.target.strip())
    return result

@router.post("/answer")
async def answer_question(payload: AnswerRequest):
    """
    Answer a question from the orchestrator or skip an engine.
    Example answers:
    - low_token | high_token
    - skip bola
    """
    result = orchestrator.answer_question(payload.session_id, payload.answer)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result

@router.post("/run")
async def run_scan(payload: RunScanRequest):
    """
    Run all remaining engines for the session.
    """
    result = await orchestrator.run_scan(payload.session_id)
    if "error" in result and "questions" in result:
        raise HTTPException(status_code=400, detail=result)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result