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
                    tool TEXT,
                    source TEXT NOT NULL DEFAULT 'unknown',
                    trusted_source INTEGER NOT NULL DEFAULT 1,
                    resource TEXT,
                    parameters TEXT,
                    timestamp TEXT NOT NULL,
                    is_malicious INTEGER NOT NULL DEFAULT 0,
                    threat_type TEXT DEFAULT 'none',
                    ml_confidence REAL DEFAULT 0.0,
                    ml_reason TEXT,
                    risk_score REAL DEFAULT 0.0,
                    decision TEXT NOT NULL,
                    decision_reason TEXT,
                    threat_types TEXT NOT NULL DEFAULT '[]',
                    execution_status TEXT NOT NULL DEFAULT 'not_requested',
                    access_decision TEXT NOT NULL DEFAULT 'ALLOW',
                    data_leakage_detected INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS agent_approvals (
                    approval_id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    action_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN (
                            'pending', 'processing', 'approved',
                            'rejected', 'expired', 'blocked'
                        )),
                    requested_at TEXT NOT NULL,
                    reviewer TEXT,
                    resolution_event_id TEXT
                );
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_approvals_status "
                "ON agent_approvals(status, requested_at DESC);"
            )
            columns = {
                row["name"] for row in conn.execute("PRAGMA table_info(security_events)")
            }
            if "source" not in columns:
                conn.execute(
                    "ALTER TABLE security_events ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown';"
                )
            for column, declaration in (
                ("tool", "TEXT"),
                ("trusted_source", "INTEGER NOT NULL DEFAULT 1"),
                ("threat_types", "TEXT NOT NULL DEFAULT '[]'"),
                ("execution_status", "TEXT NOT NULL DEFAULT 'not_requested'"),
                ("access_decision", "TEXT NOT NULL DEFAULT 'ALLOW'"),
                ("data_leakage_detected", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in columns:
                    conn.execute(
                        f"ALTER TABLE security_events ADD COLUMN {column} {declaration};"
                    )
            # Create indexes for fast filtering
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_decision ON security_events(decision);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_threat_type ON security_events(threat_type);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_agent_id ON security_events(agent_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_action_id ON security_events(action_id);")
            conn.commit()

    def create_approval(
        self,
        approval_id: str,
        event_id: str,
        action_json: str,
        requested_at: str,
    ) -> None:
        """Persist an action awaiting explicit human review."""
        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT INTO agent_approvals (
                    approval_id, event_id, action_json, status, requested_at
                ) VALUES (?, ?, ?, 'pending', ?);
                """,
                (approval_id, event_id, action_json, requested_at),
            )
            conn.commit()

    def list_approvals(self, status: str = "pending") -> List[Dict[str, Any]]:
        """List approval requests without exposing stored action instructions."""
        with self.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT approval_id, event_id, action_json, status, requested_at,
                       reviewer, resolution_event_id
                FROM agent_approvals
                WHERE status = ?
                ORDER BY requested_at DESC;
                """,
                (status,),
            ).fetchall()
            return [self._row_to_approval(row) for row in rows]

    def claim_approval(
        self,
        approval_id: str,
        expired_before: str,
    ) -> Optional[Dict[str, Any]]:
        """Atomically claim a pending approval once, marking stale requests expired."""
        with self.get_connection() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute(
                """
                SELECT approval_id, event_id, action_json, status, requested_at,
                       reviewer, resolution_event_id
                FROM agent_approvals
                WHERE approval_id = ?;
                """,
                (approval_id,),
            ).fetchone()
            if row is None or row["status"] != "pending":
                return None
            next_status = (
                "expired" if row["requested_at"] < expired_before else "processing"
            )
            conn.execute(
                """
                UPDATE agent_approvals
                SET status = ?, action_json = CASE
                    WHEN ? = 'expired' THEN '{}' ELSE action_json
                END
                WHERE approval_id = ? AND status = 'pending';
                """,
                (next_status, next_status, approval_id),
            )
            claimed = conn.execute(
                """
                SELECT approval_id, event_id, action_json, status, requested_at,
                       reviewer, resolution_event_id
                FROM agent_approvals
                WHERE approval_id = ?;
                """,
                (approval_id,),
            ).fetchone()
            return self._row_to_approval(claimed) if claimed is not None else None

    def resolve_approval(
        self,
        approval_id: str,
        status: str,
        reviewer: str,
        resolution_event_id: str,
    ) -> bool:
        """Finish a claimed request; returns false if it is no longer processing."""
        with self.get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE agent_approvals
                SET status = ?, action_json = '{}', reviewer = ?,
                    resolution_event_id = ?
                WHERE approval_id = ? AND status = 'processing';
                """,
                (status, reviewer, resolution_event_id, approval_id),
            )
            conn.commit()
            return cursor.rowcount == 1

    @staticmethod
    def _row_to_approval(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "approval_id": row["approval_id"],
            "event_id": row["event_id"],
            "action": json.loads(row["action_json"]),
            "status": row["status"],
            "requested_at": row["requested_at"],
            "reviewer": row["reviewer"],
            "resolution_event_id": row["resolution_event_id"],
        }

    def insert_event(self, event: SecurityEvent) -> SecurityEvent:
        """Insert a unified security event using safe parameterized query."""
        params_json = json.dumps(event.parameters) if isinstance(event.parameters, dict) else "{}"
        is_mal_int = 1 if event.is_malicious else 0

        with self.get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO security_events (
                    event_id, action_id, agent_id, action_type, tool, source, trusted_source, resource,
                    parameters, timestamp, is_malicious, threat_type,
                    ml_confidence, ml_reason, risk_score, decision, decision_reason,
                    threat_types, execution_status, access_decision, data_leakage_detected
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    event.event_id,
                    event.action_id,
                    event.agent_id,
                    event.action_type,
                    event.tool,
                    event.source,
                    int(event.trusted_source),
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
                    json.dumps(event.threat_types),
                    event.execution_status,
                    event.access_decision,
                    int(event.data_leakage_detected),
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
        source: Optional[str] = None,
        execution_status: Optional[str] = None,
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
        if source:
            query += " AND LOWER(source) = LOWER(?)"
            params.append(source)
        if execution_status:
            query += " AND LOWER(execution_status) = LOWER(?)"
            params.append(execution_status)

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
        source: Optional[str] = None,
        execution_status: Optional[str] = None,
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
        if source:
            query += " AND LOWER(source) = LOWER(?)"
            params.append(source)
        if execution_status:
            query += " AND LOWER(execution_status) = LOWER(?)"
            params.append(execution_status)

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
            tool=row["tool"] if "tool" in row.keys() else None,
            source=row["source"] if "source" in row.keys() else "unknown",
            trusted_source=(
                bool(row["trusted_source"]) if "trusted_source" in row.keys() else True
            ),
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
            threat_types=(
                json.loads(row["threat_types"] or "[]")
                if "threat_types" in row.keys()
                else ([row["threat_type"]] if row["threat_type"] not in (None, "", "none") else [])
            ),
            execution_status=(
                row["execution_status"]
                if "execution_status" in row.keys()
                else "not_requested"
            ),
            access_decision=(
                row["access_decision"] if "access_decision" in row.keys() else "ALLOW"
            ),
            data_leakage_detected=(
                bool(row["data_leakage_detected"])
                if "data_leakage_detected" in row.keys()
                else False
            ),
        )


# Global singleton instance
db = Database()
