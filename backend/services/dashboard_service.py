"""Dashboard Service computing live metrics and analytics from actual stored events."""

from typing import Dict, Any, Optional
from backend.database import Database, db as default_db


class DashboardService:
    """Computes aggregated security posture statistics directly from the database."""

    def __init__(self, database: Optional[Database] = None):
        self.db = database or default_db

    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Calculate and return dashboard statistics from stored security events.
        
        Returns:
            Dictionary with:
            - total_events
            - allowed
            - blocked
            - approval_required
            - threats_detected
            - threat_breakdown
            - decision_breakdown
        """
        return self.db.get_stats()


# Global service instance
dashboard_service = DashboardService()
