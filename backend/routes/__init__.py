"""Routes package initialization."""

from .health import router as health_router
from .events import router as events_router
from .decisions import router as decisions_router

__all__ = ["health_router", "events_router", "decisions_router"]
