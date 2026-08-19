from typing import Dict, List
from fastapi import WebSocket
import logging

logger = logging.getLogger("ConnectionManager")

class ConnectionManager:
    """
    Manages active WebSocket connections for real-time updates.
    """

    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, job_id: str, websocket: WebSocket):
        await websocket.accept()
        if job_id not in self.active_connections:
            self.active_connections[job_id] = []
        self.active_connections[job_id].append(websocket)
        logger.info(f"WebSocket connected for job {job_id}. Total: {len(self.active_connections[job_id])}")

    def disconnect(self, job_id: str, websocket: WebSocket):
        if job_id in self.active_connections:
            if websocket in self.active_connections[job_id]:
                self.active_connections[job_id].remove(websocket)
            if not self.active_connections[job_id]:
                del self.active_connections[job_id]
            logger.info(f"WebSocket disconnected for job {job_id}")

    async def send_message(self, job_id: str, message: dict):
        if job_id in self.active_connections:
            dead_connections = []
            for connection in self.active_connections[job_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.append(connection)

            for dead in dead_connections:
                self.disconnect(job_id, dead)

    def get_connection_count(self, job_id: str) -> int:
        return len(self.active_connections.get(job_id, []))

# Global manager instance
manager = ConnectionManager()