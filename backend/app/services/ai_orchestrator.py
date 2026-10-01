from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from datetime import datetime

from app.schemas.domain import (
    EngineType,
    JobCreate,
    Job,
    JobStatus,
    IdentityPair,
    EngineResult,
)
from app.services.job_service import job_service
from app.services.engine_runner import run_engine_for_job

class AIOrchestrator:
    """
    Simple AI-style orchestrator for the chat interface.
    Decides which engines to run and handles missing data / skip logic.
    """

    def __init__(self):
        # conversation_id -> state
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def start_session(self, target: str) -> Dict[str, Any]:
        """Start a new scan session from a target URL/domain."""
        session_id = str(uuid4())

        self.sessions[session_id] = {
            "target": target,
            "status": "collecting",
            "engines_to_run": [
                EngineType.SECURITY_HEADERS,
                EngineType.OPEN_REDIRECT,
                EngineType.REFLECTED_XSS,
                EngineType.SQL_INJECTION,
                EngineType.SUBDOMAIN_TAKEOVER,
                EngineType.BOLA,  # may need extra data
            ],
            "completed_engines": [],
            "skipped_engines": [],
            "pending_questions": [],
            "identity_pair": None,
            "results": [],
            "created_at": datetime.utcnow().isoformat(),
        }

        # Check what data is missing
        questions = self._get_missing_data_questions(session_id)

        return {
            "session_id": session_id,
            "message": f"Target set to: {target}\nI will scan for multiple vulnerabilities.",
            "questions": questions,
            "status": "collecting" if questions else "ready",
        }

    def _get_missing_data_questions(self, session_id: str) -> List[Dict[str, str]]:
        session = self.sessions.get(session_id)
        if not session:
            return []

        questions = []

        # BOLA needs tokens
        if EngineType.BOLA in session["engines_to_run"] and not session.get("identity_pair"):
            questions.append({
                "engine": "bola",
                "field": "identity_pair",
                "question": "BOLA scan needs two tokens (low & high privilege). Provide them or type 'skip bola'.",
                "type": "tokens"
            })

        return questions

    def answer_question(self, session_id: str, answer: str) -> Dict[str, Any]:
        """Handle user answers or skip commands."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        answer_lower = answer.strip().lower()

        # Handle skip
        if answer_lower.startswith("skip "):
            engine_name = answer_lower.replace("skip ", "").strip()
            return self._skip_engine(session_id, engine_name)

        if answer_lower == "skip bola":
            return self._skip_engine(session_id, "bola")

        # Try to parse tokens for BOLA (simple format: low_token | high_token)
        if "|" in answer and not session.get("identity_pair"):
            parts = [p.strip() for p in answer.split("|", 1)]
            if len(parts) == 2 and parts[0] and parts[1]:
                session["identity_pair"] = {
                    "low_privilege_token": parts[0],
                    "high_privilege_token": parts[1],
                    "low_privilege_user_id": "low_user",
                    "high_privilege_user_id": "high_user",
                }
                questions = self._get_missing_data_questions(session_id)
                return {
                    "message": "BOLA tokens saved.",
                    "questions": questions,
                    "status": "ready" if not questions else "collecting",
                }

        return {
            "message": "I didn't understand. For BOLA tokens send: low_token | high_token  or type 'skip bola'",
            "questions": self._get_missing_data_questions(session_id),
            "status": "collecting",
        }

    def _skip_engine(self, session_id: str, engine_name: str) -> Dict[str, Any]:
        session = self.sessions[session_id]
        engine_map = {
            "bola": EngineType.BOLA,
            "xss": EngineType.REFLECTED_XSS,
            "sqli": EngineType.SQL_INJECTION,
            "sql": EngineType.SQL_INJECTION,
            "headers": EngineType.SECURITY_HEADERS,
            "redirect": EngineType.OPEN_REDIRECT,
            "subdomain": EngineType.SUBDOMAIN_TAKEOVER,
        }

        engine = engine_map.get(engine_name)
        if engine and engine in session["engines_to_run"]:
            session["engines_to_run"].remove(engine)
            session["skipped_engines"].append(engine.value)

        questions = self._get_missing_data_questions(session_id)
        return {
            "message": f"Skipped: {engine_name}",
            "questions": questions,
            "status": "ready" if not questions else "collecting",
            "skipped_engines": session["skipped_engines"],
        }

    async def run_scan(self, session_id: str) -> Dict[str, Any]:
        """Run all remaining engines for the session."""
        session = self.sessions.get(session_id)
        if not session:
            return {"error": "Session not found"}

        if session["status"] == "collecting" and self._get_missing_data_questions(session_id):
            return {
                "error": "Still waiting for required data. Answer the questions or skip.",
                "questions": self._get_missing_data_questions(session_id),
            }

        session["status"] = "running"
        target = session["target"]
        results = []

        for engine_type in list(session["engines_to_run"]):
            job_create = JobCreate(
                engine=engine_type,
                target=target,
                additional_targets=[],
                options={
                    "use_ai_payloads": True,
                    "depth": "normal",
                },
                timeout_seconds=30,
            )

            # Attach identity pair for BOLA
            if engine_type == EngineType.BOLA and session.get("identity_pair"):
                ip = session["identity_pair"]
                job_create.identity_pair = IdentityPair(
                    low_privilege_token=ip["low_privilege_token"],
                    high_privilege_token=ip["high_privilege_token"],
                    low_privilege_user_id=ip.get("low_privilege_user_id", "low_user"),
                    high_privilege_user_id=ip.get("high_privilege_user_id", "high_user"),
                )

            job = job_service.create_job(job_create)
            result = await run_engine_for_job(job)

            results.append({
                "engine": engine_type.value,
                "success": result.success,
                "findings_count": len(result.findings),
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "error": result.error,
                "duration_seconds": result.duration_seconds,
                "job_id": str(job.id),
            })

            session["completed_engines"].append(engine_type.value)

        session["results"] = results
        session["status"] = "completed"

        total_findings = sum(r["findings_count"] for r in results)

        return {
            "session_id": session_id,
            "status": "completed",
            "message": f"Scan completed. {total_findings} total finding(s) across {len(results)} engines.",
            "results": results,
            "skipped_engines": session["skipped_engines"],
            "total_findings": total_findings,
        }

# Global instance
orchestrator = AIOrchestrator()