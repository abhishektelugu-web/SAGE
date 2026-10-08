"""Event Service for managing and retrieving SAGE security events."""

import datetime
import uuid
from typing import List, Optional, Dict, Any
from shared.event import SecurityEvent
from backend.database import Database, db as default_db
from backend.logging.audit_logger import AuditLogger, audit_logger as default_logger
from backend.schemas.api_schemas import SecurityEventCreate


class EventService:
    """Service handling ingestion, retrieval, and filtering of security events."""

    def __init__(
        self,
        database: Optional[Database] = None,
        logger: Optional[AuditLogger] = None,
    ):
        self.db = database or default_db
        self.logger = logger or default_logger

    def record_event(self, data: SecurityEventCreate) -> SecurityEvent:
        """Create and store a unified security event from validated schema."""
        event_id = data.event_id or f"EVT-{uuid.uuid4().hex[:10].upper()}"
        timestamp = data.timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()

        event = SecurityEvent(
            event_id=event_id,
            action_id=data.action_id,
            agent_id=data.agent_id,
            action_type=data.action_type,
            resource=data.resource,
            parameters=data.parameters,
            timestamp=timestamp,
            is_malicious=data.is_malicious,
            threat_type=data.threat_type or "none",
            ml_confidence=float(data.ml_confidence),
            ml_reason=data.ml_reason,
            risk_score=float(data.risk_score),
            decision=data.decision.upper(),
            decision_reason=data.decision_reason,
        )

        # Log and persist safely
        return self.logger.log_event(event)

    def get_event(self, event_id: str) -> Optional[SecurityEvent]:
        """Retrieve single security event by its unique ID."""
        return self.db.get_event_by_id(event_id)

    def get_event_by_action(self, action_id: str) -> Optional[SecurityEvent]:
        """Retrieve security event correlated with action ID."""
        return self.db.get_event_by_action_id(action_id)

    def list_events(
        self,
        decision: Optional[str] = None,
        threat_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[SecurityEvent]:
        """Retrieve stored security events with optional filtering."""
        return self.db.list_events(
            decision=decision,
            threat_type=threat_type,
            agent_id=agent_id,
            limit=limit,
            offset=offset,
        )

    def count_events(
        self,
        decision: Optional[str] = None,
        threat_type: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> int:
        """Count events matching specified filters."""
        return self.db.count_events(
            decision=decision,
            threat_type=threat_type,
            agent_id=agent_id,
        )


# Global service instance
event_service = EventService()
