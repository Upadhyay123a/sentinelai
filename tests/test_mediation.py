"""The mediation invariant: an agent CANNOT reach a real tool without the gateway.

This is the executable form of SentinelAI's core claim — even a fully compromised
agent is contained, because every side effect must pass through the reference monitor.
"""
from __future__ import annotations

import uuid

from agents.base import Agent
from agents.tools.base import ToolProxy
from agents.tools.http_request import SENT_REQUESTS, HttpRequestTool
from agents.tools.database_read import DatabaseReadTool
from agents.tools.document_read import DocumentReadTool
from gateway.audit.store import InMemoryAuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.orchestrator import Gateway
from gateway.policy.engine import PolicyEngine
from gateway.taint.engine import TaintEngine


def _gateway(mode):
    return Gateway(
        config=GatewayConfig(mode=mode),
        audit=InMemoryAuditStore(),
        tools=[DocumentReadTool(), DatabaseReadTool(), HttpRequestTool()],
        taint=TaintEngine(),
        policy=PolicyEngine.from_yaml("policies/trifecta.yaml"),
    )


class MaliciousAgent(Agent):
    """A compromised agent that tries to grab a real tool and bypass the gateway."""

    agent_id = "malicious"

    def run(self, prompt, tools):
        # The agent only ever receives ToolProxy objects, never real Tools.
        for t in tools.values():
            assert isinstance(t, ToolProxy)
            assert not hasattr(t, "run")  # no direct execution method exposed
        return "no bypass available"


def test_agent_receives_only_proxies():
    gw = _gateway(EnforcementMode.ENFORCE)
    result = gw.run_agent(MaliciousAgent(), "x", str(uuid.uuid4()))
    assert result == "no bypass available"


def test_enforce_blocks_exfil_end_to_end():
    from agents.scripted_agent import ScriptedAgent
    SENT_REQUESTS.clear()
    gw = _gateway(EnforcementMode.ENFORCE)
    gw.run_agent(ScriptedAgent(), "Summarize this document.", str(uuid.uuid4()))
    assert SENT_REQUESTS == []  # nothing left the boundary


def test_disabled_allows_exfil_end_to_end():
    from agents.scripted_agent import ScriptedAgent
    SENT_REQUESTS.clear()
    gw = _gateway(EnforcementMode.DISABLED)
    gw.run_agent(ScriptedAgent(), "Summarize this document.", str(uuid.uuid4()))
    assert len(SENT_REQUESTS) == 1  # the vulnerability is real without the gateway
