"""The SentinelAI gateway: the reference monitor that mediates every tool call."""
from __future__ import annotations

from typing import Any, Mapping

from agents.base import Agent
from agents.tools.base import Tool, ToolProxy
from gateway.audit.store import AuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.events import Decision, EventType, SecurityEvent


class Gateway:
    def __init__(
        self, config: GatewayConfig, audit: AuditStore, tools: list[Tool]
    ) -> None:
        self._config = config
        self._audit = audit
        self._tools = {t.spec.name: t for t in tools}

    def run_agent(self, agent: Agent, prompt: str, session_id: str) -> str:
        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.AGENT_INVOCATION,
                agent_id=agent.agent_id,
                arguments={"prompt": prompt},
            )
        )
        # Hand the agent ONLY proxies — never the real tools.
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

        # --- M2 will insert the analysis pipeline here: --------------------
        #   taint facts -> risk score -> policy decision (ALLOW/BLOCK/APPROVE)
        # In M1 (DISABLED) we make no decision and simply pass through.
        decision = Decision.ALLOW
        # -------------------------------------------------------------------

        if self._config.mode == EnforcementMode.ENFORCE and decision == Decision.BLOCK:
            self._audit.append(
                SecurityEvent(
                    session_id=session_id,
                    type=EventType.TOOL_BLOCKED,
                    agent_id=agent_id,
                    tool=tool.spec.name,
                    arguments=arguments,
                    decision=decision,
                )
            )
            return "[BLOCKED by SentinelAI]"

        result = tool.run(**arguments)
        self._audit.append(
            SecurityEvent(
                session_id=session_id,
                type=EventType.TOOL_EXECUTED,
                agent_id=agent_id,
                tool=tool.spec.name,
                arguments=arguments,
                decision=decision,
            )
        )
        return result
