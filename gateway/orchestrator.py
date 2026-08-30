"""The SentinelAI gateway: the reference monitor that mediates every tool call."""
from __future__ import annotations

from typing import Any, Mapping

from agents.base import Agent
from agents.tools.base import Tool, ToolProxy
from gateway.audit.store import AuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.events import Decision, EventType, SecurityEvent
from gateway.policy.engine import PolicyEngine
from gateway.risk import engine as risk
from gateway.taint.engine import TaintEngine


class Gateway:
    def __init__(
        self,
        config: GatewayConfig,
        audit: AuditStore,
        tools: list[Tool],
        taint: TaintEngine,
        policy: PolicyEngine,
    ) -> None:
        self._config = config
        self._audit = audit
        self._tools = {t.spec.name: t for t in tools}
        self._taint = taint
        self._policy = policy

    def run_agent(self, agent: Agent, prompt: str, session_id: str) -> str:
        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.AGENT_INVOCATION,
                agent_id=agent.agent_id,
                arguments={"prompt": prompt},
            )
        )
        proxies: Mapping[str, ToolProxy] = {
            name: ToolProxy(tool, self, session_id, agent.agent_id)
            for name, tool in self._tools.items()
        }
        result = agent.run(prompt, proxies)
        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.AGENT_RESPONSE,
                agent_id=agent.agent_id,
                detail=result,
            )
        )
        return result

    def handle_tool_call(
        self, *, tool: Tool, arguments: dict[str, Any], session_id: str, agent_id: str
    ) -> Any:
        """Every ToolProxy call lands here. This is the single choke point."""
        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.TOOL_CALL_REQUESTED,
                agent_id=agent_id,
                tool=tool.spec.name,
                arguments=arguments,
            )
        )

        # DISABLED: pure pass-through, no analysis (the "SentinelAI off" baseline).
        if self._config.mode == EnforcementMode.DISABLED:
            return self._execute(tool, arguments, session_id, agent_id, Decision.ALLOW, 0)

        # MONITOR / ENFORCE run the IDENTICAL analysis pipeline.
        facts = self._taint.facts_for(session_id, tool.spec, arguments)
        risk_score = risk.score(facts)
        verdict = self._policy.evaluate(facts.as_dict())
        severity = verdict.severity or risk.band(risk_score)
        evidence = [e.event_id for e in self._audit.by_session(session_id)]

        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.POLICY_DECISION,
                agent_id=agent_id,
                tool=tool.spec.name,
                arguments=arguments,
                decision=verdict.decision,
                matched_policies=verdict.matched,
                severity=severity,
                risk_score=risk_score,
                references=verdict.references,
                evidence=evidence,
            )
        )

        # Only ENFORCE acts on a BLOCK. MONITOR detects but lets it run.
        if self._config.mode == EnforcementMode.ENFORCE and verdict.decision == Decision.BLOCK:
            self._audit.append(
                SecurityEvent(
                    session_id=session_id,
                    type=EventType.TOOL_BLOCKED,
                    agent_id=agent_id,
                    tool=tool.spec.name,
                    arguments=arguments,
                    decision=verdict.decision,
                    matched_policies=verdict.matched,
                    severity=severity,
                    risk_score=risk_score,
                    references=verdict.references,
                    evidence=evidence,
                )
            )
            return f"[BLOCKED by SentinelAI — policy: {', '.join(verdict.matched)}]"

        return self._execute(
            tool, arguments, session_id, agent_id, verdict.decision, risk_score
        )

    def _execute(
        self,
        tool: Tool,
        arguments: dict[str, Any],
        session_id: str,
        agent_id: str,
        decision: Decision,
        risk_score: int,
    ) -> Any:
        result = tool.run(**arguments)
        self._taint.observe_execution(session_id, tool.spec, result)
        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.TOOL_EXECUTED,
                agent_id=agent_id,
                tool=tool.spec.name,
                arguments=arguments,
                decision=decision,
                risk_score=risk_score,
            )
        )
        return result
