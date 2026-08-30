"""End-to-end acceptance tests for the flagship scenario (MVP criteria 1-3)."""
from __future__ import annotations

import uuid

from agents.scripted_agent import ScriptedAgent
from agents.tools.database_read import DatabaseReadTool
from agents.tools.document_read import DocumentReadTool
from agents.tools.http_request import SENT_REQUESTS, HttpRequestTool
from gateway.audit.store import InMemoryAuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.events import Decision, EventType, Severity
from gateway.orchestrator import Gateway
from gateway.policy.engine import PolicyEngine
from gateway.taint.engine import TaintEngine


def _run(mode):
    SENT_REQUESTS.clear()
    audit = InMemoryAuditStore()
    gw = Gateway(
        config=GatewayConfig(mode=mode),
        audit=audit,
        tools=[DocumentReadTool(), DatabaseReadTool(), HttpRequestTool()],
        taint=TaintEngine(),
        policy=PolicyEngine.from_yaml("policies/trifecta.yaml"),
    )
    sid = str(uuid.uuid4())
    gw.run_agent(ScriptedAgent(), "Summarize this document.", sid)
    return audit.by_session(sid)


def test_criterion_1_attack_succeeds_when_disabled():
    _run(EnforcementMode.DISABLED)
    assert SENT_REQUESTS and "sk-live-abc123SECRET" in SENT_REQUESTS[0]["body"]


def test_criterion_2_attack_blocked_when_enforced():
    _run(EnforcementMode.ENFORCE)
    assert SENT_REQUESTS == []


def test_criterion_3_evidence_chain_is_recorded():
    events = _run(EnforcementMode.ENFORCE)
    blocked = [e for e in events if e.type == EventType.TOOL_BLOCKED]
    assert len(blocked) == 1
    e = blocked[0]
    assert e.decision == Decision.BLOCK
    assert e.severity == Severity.CRITICAL
    assert "no-sensitive-exfil-under-untrusted-influence" in e.matched_policies
    assert e.evidence  # points back to the prior events forming the chain
