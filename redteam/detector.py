"""Detector: reads a probe's audit trail and reports the enforced outcome."""
from __future__ import annotations

from gateway.events import Decision, EventType, SecurityEvent


def enforced_outcome(events: list[SecurityEvent]) -> tuple[Decision, list[str]]:
    """Return the actual enforced decision on the egress attempt.

    BLOCK (with matched policy ids) if the gateway blocked a tool; else ALLOW.
    """
    for e in events:
        if e.type == EventType.TOOL_BLOCKED:
            return Decision.BLOCK, list(e.matched_policies)
    return Decision.ALLOW, []
