"""Unit tests for the policy engine: matching and deny-overrides combining."""
from __future__ import annotations

from gateway.events import Decision, Severity
from gateway.policy.engine import PolicyEngine, PolicyRule


def _rule(rid, decision, match, severity=Severity.HIGH):
    return PolicyRule(id=rid, description="", match=match, decision=decision,
                      severity=severity, references=[])


def test_no_match_defaults_to_allow():
    engine = PolicyEngine([_rule("r1", Decision.BLOCK, {"call.is_external_sink": True})])
    result = engine.evaluate({"call.is_external_sink": False})
    assert result.decision == Decision.ALLOW
    assert result.matched == []


def test_single_block_rule_matches():
    engine = PolicyEngine([_rule("r1", Decision.BLOCK, {"call.is_external_sink": True})])
    result = engine.evaluate({"call.is_external_sink": True})
    assert result.decision == Decision.BLOCK
    assert result.matched == ["r1"]


def test_deny_overrides_beats_approval_and_allow():
    engine = PolicyEngine([
        _rule("approve", Decision.REQUIRE_APPROVAL, {"a": True}),
        _rule("block", Decision.BLOCK, {"b": True}),
    ])
    result = engine.evaluate({"a": True, "b": True})
    assert result.decision == Decision.BLOCK


def test_flagship_yaml_blocks_trifecta():
    engine = PolicyEngine.from_yaml("policies/trifecta.yaml")
    facts = {
        "call.is_external_sink": True,
        "call.args_contain_sensitive_value": True,
        "session.has_untrusted_ingest": True,
        "session.has_sensitive_access": True,
    }
    result = engine.evaluate(facts)
    assert result.decision == Decision.BLOCK
    assert result.severity == Severity.CRITICAL
    assert "OWASP-LLM01" in result.references
