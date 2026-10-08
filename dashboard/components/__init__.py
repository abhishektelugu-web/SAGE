"""Dashboard components package initialization."""

from .metrics import render_metrics
from .threat_chart import render_threat_charts
from .event_table import render_event_table

__all__ = ["render_metrics", "render_threat_charts", "render_event_table"]
