from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.api.routes import jobs

settings = get_settings()

app = FastAPI(
    title=settings.APP_NAME,
    debug=settings.DEBUG,
    version="0.1.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(jobs.router, prefix=settings.API_PREFIX)

@app.get("/")
async def root():
    return {
        "message": "Unified Vulnerability Scanner is running",
        "environment": settings.APP_ENV,
        "docs": "/docs",
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}