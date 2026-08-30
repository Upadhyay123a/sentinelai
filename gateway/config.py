"""Runtime configuration for SentinelAI, including the gateway enforcement mode."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EnforcementMode(str, Enum):
    """How the gateway acts on its decisions.

    DISABLED: pass every tool call straight through, no analysis (attack succeeds).
    MONITOR:  run full analysis + audit, but do NOT enforce decisions.
    ENFORCE:  run full analysis + audit AND enforce (BLOCK / REQUIRE_APPROVAL).
    """

    DISABLED = "DISABLED"
    MONITOR = "MONITOR"
    ENFORCE = "ENFORCE"


@dataclass(frozen=True)
class GatewayConfig:
    mode: EnforcementMode = EnforcementMode.DISABLED
