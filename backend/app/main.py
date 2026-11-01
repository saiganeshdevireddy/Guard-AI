"""
Guard AI - Main FastAPI Application Server.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.core.audit_chain import AuditChainService
from app.database import SessionLocal, init_db
from app.routers import (
    agents_api,
    android_api,
    audit_api,
    emergency_api,
    sandbox_api,
    scanner_api,
    vault_api,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize Database and Genesis Audit Record
    init_db()
    db = SessionLocal()
    try:
        from app.database import AuditEntry
        if not db.query(AuditEntry).first():
            AuditChainService.record_event(
                db,
                actor="Guard AI Genesis Engine",
                event_type="SYSTEM_GENESIS_INITIALIZED",
                payload={"version": settings.VERSION, "platform": "Windows/Android Ready"}
            )
    finally:
        db.close()
    yield
    # Shutdown logic if any


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Multi-Agent AI Cybersecurity & Privacy Protection Platform",
    lifespan=lifespan,
)

# CORS Middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits Vite frontend on any port/host
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register All API Routers
app.include_router(agents_api.router, prefix=settings.API_V1_STR)
app.include_router(scanner_api.router, prefix=settings.API_V1_STR)
app.include_router(vault_api.router, prefix=settings.API_V1_STR)
app.include_router(audit_api.router, prefix=settings.API_V1_STR)
app.include_router(emergency_api.router, prefix=settings.API_V1_STR)
app.include_router(sandbox_api.router, prefix=settings.API_V1_STR)
app.include_router(android_api.router, prefix=settings.API_V1_STR)


@app.get("/api/health")
def health_check():
    """System health check and diagnostic ping."""
    return {
        "status": "OPERATIONAL",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "privacy_mode": "LOCAL_ONLY" if settings.LOCAL_ONLY_MODE else "HYBRID_CLOUD",
        "database": "SQLite Initialized",
        "encryption": "AES-256-GCM / PBKDF2 Active"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
