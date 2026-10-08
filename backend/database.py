"""Persistent SQLite Database Layer for SAGE AI Backend."""

import os
import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from shared.event import SecurityEvent


DEFAULT_DB_PATH = os.getenv("SAGE_DB_PATH", str(Path(__file__).resolve().parent.parent / "sage.db"))


class Database:
    """SQLite Database manager providing thread-safe parameterized operations."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        # Ensure parent directory exists
        db_parent = Path(self.db_path).parent
        if db_parent and not db_parent.exists():
            db_parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a new SQLite connection with Row factory."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.OperationalError:
            pass
        return conn

    def init_db(self) -> None:
        """Automatically create the security_events table and indexes if they do not exist."""
        with self.get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    event_id TEXT PRIMARY KEY,
                    action_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    resource TEXT,
                    parameters TEXT,
                    timestamp TEXT NOT NULL,
                    is_malicious INTEGER NOT NULL DEFAULT 0,
                    threat_type TEXT DEFAULT 'none',
                    ml_confidence REAL DEFAULT 0.0,
                    ml_reason TEXT,
                    risk_score REAL DEFAULT 0.0,
                    decision TEXT NOT NULL,
                    decision_reason TEXT
                );
                """
            )
            # Create indexes for fast filtering
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON security_events(decision);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_threat_type ON security_events(threat_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent_id ON security_events(agent_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action_id ON security_events(action_id);")
            conn.commit()

    def insert_event(self, event: SecurityEvent) -> SecurityEvent:
        """Insert a unified security event using safe parameterized query."""
        params_json = json.dumps(event.parameters) if isinstance(event.parameters, dict) else "{}"
        is_mal_int = 1 if event.is_malicious else 0

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO security_events (
                    event_id, action_id, agent_id, action_type, resource,
                    parameters, timestamp, is_malicious, threat_type,
                    ml_confidence, ml_reason, risk_score, decision, decision_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.event_id,
                    event.action_id,
                    event.agent_id,
                    event.action_type,
                    event.resource,
                    params_json,
                    event.timestamp,
                    is_mal_int,
                    event.threat_type,
                    event.ml_confidence,
                    event.ml_reason,
                    event.risk_score,
                    event.decision,
                    event.decision_reason,
                ),
            )
            conn.commit()
        return event

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        """Fetch a single security event by event_id."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM security_events WHERE event_id = ?;", (event_id,)
            ).fetchone()
            if row:
                return self._row_to_event(row)
        return None

    def get_event_by_action_id(self, action_id: str) -> Optional[SecurityEvent]:
        """Fetch a single security event by action_id."""
        with self.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM security_events WHERE action_id = ? ORDER BY timestamp DESC LIMIT 1;",
                (action_id,),
            ).fetchone()
            if row:
                return self._row_to_event(row)
        return None

    def list_events(
        self,
        decision: Optional[str] = None,
        threat_type: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[SecurityEvent]:
        """Retrieve stored security events with optional filtering."""
        query = "SELECT * FROM security_events WHERE 1=1"
        params: List[Any] = []

        if decision:
            query += " AND UPPER(decision) = UPPER(?)"
            params.append(decision)
        if threat_type:
            query += " AND LOWER(threat_type) = LOWER(?)"
            params.append(threat_type)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
            return [self._row_to_event(r) for r in rows]

    def count_events(
        self,
        decision: Optional[str] = None,
        threat_type: Optional[str] = None,
        agent_id: Optional[str] = None,
    ) -> int:
        """Count events matching filters."""
        query = "SELECT COUNT(*) AS total FROM security_events WHERE 1=1"
        params: List[Any] = []

        if decision:
            query += " AND UPPER(decision) = UPPER(?)"
            params.append(decision)
        if threat_type:
            query += " AND LOWER(threat_type) = LOWER(?)"
            params.append(threat_type)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        with self.get_connection() as conn:
            row = conn.execute(query, tuple(params)).fetchone()
            return row["total"] if row else 0

    def get_stats(self) -> Dict[str, Any]:
        """Compute aggregated dashboard statistics directly from database records."""
        with self.get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) AS count FROM security_events;").fetchone()["count"]
            allowed = conn.execute("SELECT COUNT(*) AS count FROM security_events WHERE UPPER(decision) = 'ALLOW';").fetchone()["count"]
            blocked = conn.execute("SELECT COUNT(*) AS count FROM security_events WHERE UPPER(decision) = 'BLOCK';").fetchone()["count"]
            approval_required = conn.execute("SELECT COUNT(*) AS count FROM security_events WHERE UPPER(decision) = 'APPROVAL_REQUIRED';").fetchone()["count"]
            threats_detected = conn.execute("SELECT COUNT(*) AS count FROM security_events WHERE is_malicious = 1 OR (threat_type IS NOT NULL AND threat_type != 'none' AND threat_type != '');").fetchone()["count"]

            # Threat category breakdown
            threat_rows = conn.execute(
                """
                SELECT threat_type, COUNT(*) as count 
                FROM security_events 
                WHERE threat_type IS NOT NULL AND threat_type != 'none' AND threat_type != ''
                GROUP BY threat_type
                ORDER BY count DESC;
                """
            ).fetchall()
            threat_breakdown = {r["threat_type"]: r["count"] for r in threat_rows}

            # Decision breakdown
            decision_rows = conn.execute(
                """
                SELECT decision, COUNT(*) as count
                FROM security_events
                GROUP BY decision;
                """
            ).fetchall()
            decision_breakdown = {r["decision"]: r["count"] for r in decision_rows}

            return {
                "total_events": total,
                "allowed": allowed,
                "blocked": blocked,
                "approval_required": approval_required,
                "threats_detected": threats_detected,
                "threat_breakdown": threat_breakdown,
                "decision_breakdown": decision_breakdown,
            }

    def _row_to_event(self, row: sqlite3.Row) -> SecurityEvent:
        """Convert a database row into a SecurityEvent Pydantic model."""
        params_str = row["parameters"] or "{}"
        try:
            parameters = json.loads(params_str)
        except Exception:
            parameters = {}

        return SecurityEvent(
            event_id=row["event_id"],
            action_id=row["action_id"],
            agent_id=row["agent_id"],
            action_type=row["action_type"],
            resource=row["resource"] or "*",
            parameters=parameters,
            timestamp=row["timestamp"],
            is_malicious=bool(row["is_malicious"]),
            threat_type=row["threat_type"] or "none",
            ml_confidence=float(row["ml_confidence"] or 0.0),
            ml_reason=row["ml_reason"] or "",
            risk_score=float(row["risk_score"] or 0.0),
            decision=row["decision"],
            decision_reason=row["decision_reason"] or "",
        )


# Global singleton instance
db = Database()
