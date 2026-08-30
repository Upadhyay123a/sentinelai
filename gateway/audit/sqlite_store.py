"""Persistent, append-only audit store backed by SQLite (stdlib — no new deps).

Implements the same AuditStore interface as InMemoryAuditStore, so the gateway is
unchanged: we only swap which store we hand it. Append-only is enforced by policy
here — this class contains INSERT and SELECT only, never UPDATE or DELETE.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from gateway.audit.store import AuditStore
from gateway.events import Decision, EventType, SecurityEvent, Severity

# Note: the column is named `refs`, not `references` — REFERENCES is a reserved
# SQL keyword and would break the CREATE TABLE.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT NOT NULL,
    session_id       TEXT NOT NULL,
    timestamp        TEXT NOT NULL,
    type             TEXT NOT NULL,
    agent_id         TEXT,
    tool             TEXT,
    arguments        TEXT NOT NULL DEFAULT '{}',
    decision         TEXT,
    matched_policies TEXT NOT NULL DEFAULT '[]',
    severity         TEXT,
    risk_score       INTEGER NOT NULL DEFAULT 0,
    evidence         TEXT NOT NULL DEFAULT '[]',
    refs             TEXT NOT NULL DEFAULT '[]',
    detail           TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
"""


class SqliteAuditStore(AuditStore):
    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def append(self, event: SecurityEvent) -> None:
        # append-only: INSERT only.
        self._conn.execute(
            """
            INSERT INTO events (
                event_id, session_id, timestamp, type, agent_id, tool,
                arguments, decision, matched_policies, severity,
                risk_score, evidence, refs, detail
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event.event_id,
                event.session_id,
                event.timestamp,
                event.type.value,
                event.agent_id,
                event.tool,
                json.dumps(event.arguments),
                event.decision.value if event.decision else None,
                json.dumps(event.matched_policies),
                event.severity.value if event.severity else None,
                event.risk_score,
                json.dumps(event.evidence),
                json.dumps(event.references),
                event.detail,
            ),
        )
        self._conn.commit()

    def by_session(self, session_id: str) -> list[SecurityEvent]:
        rows = self._conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY seq", (session_id,)
        ).fetchall()
        return [self._row_to_event(r) for r in rows]

    def all(self) -> list[SecurityEvent]:
        rows = self._conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
        return [self._row_to_event(r) for r in rows]

    def sessions(self) -> list[str]:
        rows = self._conn.execute(
            "SELECT session_id, MIN(seq) AS first FROM events "
            "GROUP BY session_id ORDER BY first"
        ).fetchall()
        return [r["session_id"] for r in rows]

    @staticmethod
    def _row_to_event(r: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            session_id=r["session_id"],
            type=EventType(r["type"]),
            event_id=r["event_id"],
            timestamp=r["timestamp"],
            agent_id=r["agent_id"],
            tool=r["tool"],
            arguments=json.loads(r["arguments"]),
            decision=Decision(r["decision"]) if r["decision"] else None,
            matched_policies=json.loads(r["matched_policies"]),
            severity=Severity(r["severity"]) if r["severity"] else None,
            risk_score=r["risk_score"],
            evidence=json.loads(r["evidence"]),
            references=json.loads(r["refs"]),
            detail=r["detail"],
        )
