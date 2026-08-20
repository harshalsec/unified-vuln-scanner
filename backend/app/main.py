from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time

from app.config import get_settings
from app.api.routes import jobs
from app.api.websockets import scan as ws_scan

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    version="0.1.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
    # Basic protection against very large payloads
)

# ----------------------
# Security Headers Middleware
# ----------------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Server"] = "VulnScanner"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

app.add_middleware(SecurityHeadersMiddleware)

class LimitUploadSizeMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_upload_size: int = 1_000_000):  # 1 MB
        super().__init__(app)
        self.max_upload_size = max_upload_size

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_upload_size:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        return await call_next(request)

app.add_middleware(LimitUploadSizeMiddleware)

# ----------------------
# CORS (restrict in production)
# ----------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ----------------------
# Simple in-memory rate limiting
# ----------------------
request_counts = {}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    current_time = time.time()

    # Clean old entries
    request_counts[client_ip] = [
        t for t in request_counts.get(client_ip, []) if current_time - t < 60
    ]

    if len(request_counts.get(client_ip, [])) >= settings.RATE_LIMIT_PER_MINUTE:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please try again later."},
        )

    request_counts.setdefault(client_ip, []).append(current_time)
    response = await call_next(request)
    return response

# ----------------------
# Routes
# ----------------------
app.include_router(jobs.router, prefix=settings.API_PREFIX)
app.include_router(ws_scan.router)

@app.get("/")
async def root():
    return {
        "message": "Unified Vulnerability Scanner is running",
        "environment": settings.APP_ENV,
        "version": "0.1.0",
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}