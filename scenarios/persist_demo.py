"""Persistence demo: run the flagship attack (ENFORCE) into a SQLite audit store.

Proves the evidence survives the process. Afterwards, inspect the stored incident:
    python -m gateway.audit.view sentinelai.db <session_id>
"""
from __future__ import annotations

import uuid

from agents.scripted_agent import ScriptedAgent
from agents.tools.database_read import DatabaseReadTool
from agents.tools.document_read import DocumentReadTool
from agents.tools.http_request import SENT_REQUESTS, HttpRequestTool
from gateway.audit.sqlite_store import SqliteAuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.orchestrator import Gateway
from gateway.policy.engine import PolicyEngine
from gateway.taint.engine import TaintEngine

DB_PATH = "sentinelai.db"


def main() -> None:
    SENT_REQUESTS.clear()
    audit = SqliteAuditStore(DB_PATH)
    gateway = Gateway(
        config=GatewayConfig(mode=EnforcementMode.ENFORCE),
        audit=audit,
        tools=[DocumentReadTool(), DatabaseReadTool(), HttpRequestTool()],
        taint=TaintEngine(),
        policy=PolicyEngine.from_yaml("policies/trifecta.yaml"),
    )
    session_id = str(uuid.uuid4())
    gateway.run_agent(ScriptedAgent(), "Summarize this document.", session_id)

    stored = audit.by_session(session_id)
    print(f"Persisted {len(stored)} events to {DB_PATH}")
    print(f"Session: {session_id}")
    print(f"Exfiltration prevented: {SENT_REQUESTS == []}")
    print(f"\nInspect it:  python -m gateway.audit.view {DB_PATH} {session_id}")


if __name__ == "__main__":
    main()
