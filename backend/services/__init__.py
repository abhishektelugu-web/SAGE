"""Services package initialization."""

from .event_service import EventService, event_service
from .dashboard_service import DashboardService, dashboard_service

__all__ = [
    "EventService",
    "event_service",
    "DashboardService",
    "dashboard_service",
]
