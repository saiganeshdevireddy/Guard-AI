"""
Guard AI - Main FastAPI Application Server.
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.config import settings
from app.core.audit_chain import AuditChainService
from app.database import SessionLocal, engine, init_db
from app.routers import (
    agents_api,
    auth_api,
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
                payload={"version": settings.VERSION, "platform": "Local prototype"}
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
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Register All API Routers
app.include_router(agents_api.router, prefix=settings.API_V1_STR)
app.include_router(auth_api.router, prefix="/api")
app.include_router(scanner_api.router, prefix=settings.API_V1_STR)
app.include_router(vault_api.router, prefix=settings.API_V1_STR)
app.include_router(audit_api.router, prefix=settings.API_V1_STR)
app.include_router(emergency_api.router, prefix=settings.API_V1_STR)
app.include_router(sandbox_api.router, prefix=settings.API_V1_STR)
app.include_router(android_api.router, prefix=settings.API_V1_STR)


@app.get("/api/health")
def health_check():
    """System health check and diagnostic ping."""
    database_status = "OPERATIONAL"
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        database_status = "UNAVAILABLE"
    return {
        "status": "OPERATIONAL" if database_status == "OPERATIONAL" else "DEGRADED",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "privacy_mode": "LOCAL_ONLY" if settings.LOCAL_ONLY_MODE else "HYBRID_CLOUD",
        "database": database_status,
        "encryption": "AES-256-GCM / PBKDF2 configured",
        "features": {"android_companion": "UNPAIRED", "isolated_remote_preview": "DISABLED"},
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
