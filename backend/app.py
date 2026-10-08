"""FastAPI Application Entry Point for SAGE AI Backend.

Provides RESTful security event APIs, health checks, and dashboard telemetry.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import db
from backend.routes.health import router as health_router
from backend.routes.events import router as events_router
from backend.routes.decisions import router as decisions_router
from backend.routes.evaluate import router as evaluate_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook: ensure database tables are created on startup."""
    db.init_db()
    yield


app = FastAPI(
    title="SAGE AI — Security Analysis & Guard Engine",
    description=(
        "Production backend for SAGE AI: Security event storage, "
        "audit logging, integration adapter, and telemetry for the security dashboard."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for dashboard or external clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(health_router)
app.include_router(events_router)
app.include_router(decisions_router)
app.include_router(evaluate_router)


@app.get("/")
def root():
    """Root metadata endpoint."""
    return {
        "service": "SAGE AI — Security Analysis & Guard Engine",
        "role": "Member 3 — Backend + Dashboard",
        "status": "online",
        "documentation": "/docs",
        "health": "/health",
        "events_endpoint": "/api/events",
        "stats_endpoint": "/api/dashboard/stats",
    }
