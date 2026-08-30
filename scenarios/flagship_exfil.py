"""Flagship demo: indirect prompt injection -> data exfiltration.

M1: runs with the gateway DISABLED, so the attack SUCCEEDS. This proves the
vulnerability is real before we build the defense (M2 adds ENFORCE).
"""
from __future__ import annotations

import uuid

from agents.scripted_agent import ScriptedAgent
from agents.tools.database_read import DatabaseReadTool
from agents.tools.document_read import DocumentReadTool
from agents.tools.http_request import SENT_REQUESTS, HttpRequestTool
from gateway.audit.store import InMemoryAuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.orchestrator import Gateway


def run(mode: EnforcementMode) -> None:
    SENT_REQUESTS.clear()
    audit = InMemoryAuditStore()
    gateway = Gateway(
        config=GatewayConfig(mode=mode),
        audit=audit,
        tools=[DocumentReadTool(), DatabaseReadTool(), HttpRequestTool()],
    )
    session_id = str(uuid.uuid4())

    print(f"\n=== SentinelAI mode: {mode.value} ===")
    gateway.run_agent(ScriptedAgent(), "Summarize this document.", session_id)

    print("\n-- audit trail --")
    for e in audit.by_session(session_id):
        line = f"  {e.type.value:22} {e.tool or ''}"
        if e.decision:
            line += f"  decision={e.decision.value}"
        print(line)

    if SENT_REQUESTS:
        print(
            f"\n[!] EXFILTRATION SUCCEEDED -> {SENT_REQUESTS[0]['url']}  "
            f"leaked: {SENT_REQUESTS[0]['body']}"
        )
    else:
        print("\n[OK] No data left the boundary.")


if __name__ == "__main__":
    run(EnforcementMode.DISABLED)
