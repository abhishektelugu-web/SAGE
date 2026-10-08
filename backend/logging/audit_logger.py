"""Structured audit logger with recursive secret redaction."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from shared.event import SecurityEvent
from backend.database import Database, db as default_db

logger = logging.getLogger("sage.audit")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class AuditLogger:
    """Sanitize event payloads before persistence and structured logging."""

    SENSITIVE_KEY_PATTERNS = [
        re.compile(pattern, re.IGNORECASE)
        for pattern in (
            r"pass(word)?", r"secret", r"token", r"api[_-]?key",
            r"auth(orization)?", r"bearer", r"private[_-]?key", r"credential",
        )
    ]
    SECRET_VALUE_PATTERNS = [
        (re.compile(r"Bearer\s+[A-Za-z0-9._~+\-/]+=*", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
        (re.compile(r"(?i)\b(?:sk|pk)_[A-Za-z0-9_-]{12,}\b"), "[REDACTED_SECRET]"),
    ]

    def __init__(self, database: Optional[Database] = None):
        self.db = database or default_db

    def sanitize_data(self, data: Any) -> Any:
        if isinstance(data, dict):
            cleaned = {}
            for key, value in data.items():
                if any(pattern.search(str(key)) for pattern in self.SENSITIVE_KEY_PATTERNS):
                    cleaned[key] = "[REDACTED_SECRET]"
                else:
                    cleaned[key] = self.sanitize_data(value)
            return cleaned
        if isinstance(data, list):
            return [self.sanitize_data(item) for item in data]
        if isinstance(data, tuple):
            return tuple(self.sanitize_data(item) for item in data)
        if isinstance(data, str):
            sanitized = data
            for pattern, replacement in self.SECRET_VALUE_PATTERNS:
                sanitized = pattern.sub(replacement, sanitized)
            return sanitized
        return data

    def log_event(self, event: SecurityEvent) -> SecurityEvent:
        safe_event = event.model_copy(update={"parameters": self.sanitize_data(event.parameters)})
        self.db.insert_event(safe_event)
        payload = {
            "audit_type": "SECURITY_EVENT",
            "event_id": safe_event.event_id,
            "action_id": safe_event.action_id,
            "agent_id": safe_event.agent_id,
            "action_type": safe_event.action_type,
            "decision": safe_event.decision,
            "threat_type": safe_event.threat_type,
            "risk_score": safe_event.risk_score,
        }
        logger.warning("AUDIT_ALERT: %s", json.dumps(payload)) if safe_event.decision == "BLOCK" else logger.info("AUDIT_LOG: %s", json.dumps(payload))
        return safe_event


audit_logger = AuditLogger()
