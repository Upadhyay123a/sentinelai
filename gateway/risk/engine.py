"""Risk engine: a deterministic, documented scoring formula.

The score communicates urgency and orders findings. The ALLOW/BLOCK decision
NEVER depends on it — that is the policy engine's job. This keeps the decision
path fully deterministic and avoids resting a security choice on a fuzzy threshold.
"""
from __future__ import annotations

from gateway.events import Severity
from gateway.taint.engine import TaintFacts


def score(facts: TaintFacts) -> int:
    total = 0
    if facts.has_untrusted_ingest:
        total += 25
    if facts.has_sensitive_access:
        total += 25
    if facts.is_external_sink:
        total += 25
    if facts.args_contain_sensitive_value:
        total += 20
    return max(0, min(100, total))


def band(value: int) -> Severity:
    if value <= 20:
        return Severity.LOW
    if value <= 40:
        return Severity.MEDIUM
    if value <= 70:
        return Severity.HIGH
    return Severity.CRITICAL
