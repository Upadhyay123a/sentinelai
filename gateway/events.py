"""Security event model and the enums used across the SentinelAI pipeline."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    AGENT_INVOCATION = "agent_invocation"
    TOOL_CALL_REQUESTED = "tool_call_requested"
    TOOL_EXECUTED = "tool_executed"
    TOOL_BLOCKED = "tool_blocked"
    POLICY_DECISION = "policy_decision"
    AGENT_RESPONSE = "agent_response"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


@dataclass
class SecurityEvent:
    session_id: str
    type: EventType
    event_id: str = field(default_factory=_new_id)
    timestamp: str = field(default_factory=_now)
    agent_id: str | None = None
    tool: str | None = None
    arguments: dict[str, Any] = field(default_factory=dict)
    decision: Decision | None = None
    matched_policies: list[str] = field(default_factory=list)
    severity: Severity | None = None
    risk_score: int = 0
    evidence: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    detail: str | None = None
