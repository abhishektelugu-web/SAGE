"""FastAPI Application Entry Point for SAGE AI Backend.

Provides RESTful security event APIs, health checks, and dashboard telemetry.
"""

from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env", override=False)

logger = logging.getLogger("uvicorn.error")

from backend.database import db
from backend.routes.health import router as health_router
from backend.routes.events import router as events_router
from backend.routes.decisions import router as decisions_router
from backend.routes.evaluate import router as evaluate_router
from backend.routes.agents import router as agents_router
from backend.routes.approvals import router as approvals_router
from ai_ml.agent_providers import (
    OpenAICompatibleProvider,
    ProviderConfigurationError,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle hook: ensure database tables are created on startup."""
    db.init_db()
    try:
        OpenAICompatibleProvider.from_environment()
    except ProviderConfigurationError:
        logger.info("OpenAI-compatible provider configuration available: false")
    else:
        logger.info("OpenAI-compatible provider configuration available: true")
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
app.include_router(agents_router)
app.include_router(approvals_router)


@app.get("/")
def root(request: Request):
    """Show the dashboard to browsers and preserve the JSON root API."""
    if "text/html" in request.headers.get("accept", ""):
        dashboard_url = os.getenv(
            "TRACEGUARD_DASHBOARD_URL", "http://127.0.0.1:8501/"
        )
        return RedirectResponse(dashboard_url)
    return {
        "service": "SAGE AI — Security Analysis & Guard Engine",
        "role": "Member 3 — Backend + Dashboard",
        "status": "online",
        "documentation": "/docs",
        "health": "/health",
        "events_endpoint": "/api/events",
        "stats_endpoint": "/api/dashboard/stats",
    }
