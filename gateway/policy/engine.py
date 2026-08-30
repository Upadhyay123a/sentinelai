"""Policy engine: policy-as-code loaded from YAML, evaluated against taint facts.

The decision is a pure function of (facts, policy) — no LLM, no randomness. Rules
combine with a deny-overrides algorithm: any BLOCK wins, else any REQUIRE_APPROVAL,
else ALLOW.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from gateway.events import Decision, Severity

_SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass(frozen=True)
class PolicyRule:
    id: str
    description: str
    match: dict[str, Any]
    decision: Decision
    severity: Severity
    references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    matched: list[str]
    severity: Severity | None
    references: list[str]


class PolicyEngine:
    def __init__(self, rules: list[PolicyRule]) -> None:
        self._rules = rules

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        raw = yaml.safe_load(Path(path).read_text()) or []
        rules = [
            PolicyRule(
                id=r["id"],
                description=r.get("description", ""),
                match=r["match"],
                decision=Decision(r["decision"]),
                severity=Severity(r["severity"]),
                references=r.get("references", []),
            )
            for r in raw
        ]
        return cls(rules)

    def evaluate(self, facts: dict[str, Any]) -> PolicyResult:
        matched = [rule for rule in self._rules if self._matches(rule, facts)]
        references: list[str] = []
        for rule in matched:
            references.extend(rule.references)
        return PolicyResult(
            decision=self._combine(matched),
            matched=[r.id for r in matched],
            severity=self._highest_severity(matched),
            references=list(dict.fromkeys(references)),  # dedupe, keep order
        )

    @staticmethod
    def _matches(rule: PolicyRule, facts: dict[str, Any]) -> bool:
        return all(facts.get(k) == v for k, v in rule.match.items())

    @staticmethod
    def _combine(matched: list[PolicyRule]) -> Decision:
        decisions = {r.decision for r in matched}
        if Decision.BLOCK in decisions:
            return Decision.BLOCK
        if Decision.REQUIRE_APPROVAL in decisions:
            return Decision.REQUIRE_APPROVAL
        return Decision.ALLOW

    @staticmethod
    def _highest_severity(matched: list[PolicyRule]) -> Severity | None:
        if not matched:
            return None
        return max(matched, key=lambda r: _SEVERITY_ORDER[r.severity]).severity
