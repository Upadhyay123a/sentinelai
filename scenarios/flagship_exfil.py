"""Flagship demo: indirect prompt injection -> data exfiltration.

Runs the SAME attack twice:
  - DISABLED (SentinelAI off): the attack SUCCEEDS, the secret is exfiltrated.
  - ENFORCE  (SentinelAI on):  the same attack is BLOCKED at the egress step.
"""
from __future__ import annotations

import uuid

from agents.scripted_agent import ScriptedAgent
from agents.tools.database_read import DatabaseReadTool
from agents.tools.document_read import DocumentReadTool
from agents.tools.http_request import SENT_REQUESTS, HttpRequestTool
from gateway.audit.store import InMemoryAuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.events import EventType
from gateway.orchestrator import Gateway
from gateway.policy.engine import PolicyEngine
from gateway.taint.engine import TaintEngine

POLICY_PATH = "policies/trifecta.yaml"


def run(mode: EnforcementMode) -> None:
    SENT_REQUESTS.clear()
    audit = InMemoryAuditStore()
    gateway = Gateway(
        config=GatewayConfig(mode=mode),
        audit=audit,
        tools=[DocumentReadTool(), DatabaseReadTool(), HttpRequestTool()],
        taint=TaintEngine(),
        policy=PolicyEngine.from_yaml(POLICY_PATH),
    )
    session_id = str(uuid.uuid4())

    print(f"\n=== SentinelAI mode: {mode.value} ===")
    gateway.run_agent(ScriptedAgent(), "Summarize this document.", session_id)

    print("-- audit trail --")
    for e in audit.by_session(session_id):
        line = f"  {e.type.value:22} {e.tool or '':14}"
        if e.decision:
            line += f" decision={e.decision.value}"
        if e.matched_policies:
            line += f" policy={','.join(e.matched_policies)}"
        if e.risk_score:
            line += f" risk={e.risk_score}"
        print(line)

    if SENT_REQUESTS:
        print(
            f"\n[!] EXFILTRATION SUCCEEDED -> {SENT_REQUESTS[0]['url']} "
            f"leaked: {SENT_REQUESTS[0]['body']}"
        )
    else:
        print("\n[OK] No data left the boundary.")
        for e in audit.by_session(session_id):
            if e.type == EventType.TOOL_BLOCKED:
                sev = e.severity.value if e.severity else ""
                print(
                    f"    BLOCKED {e.tool}: {sev} risk={e.risk_score} "
                    f"policies={','.join(e.matched_policies)}"
                )
                print(
                    f"    refs={','.join(e.references)}  "
                    f"evidence={len(e.evidence)} prior events"
                )


if __name__ == "__main__":
    run(EnforcementMode.DISABLED)
    run(EnforcementMode.ENFORCE)
