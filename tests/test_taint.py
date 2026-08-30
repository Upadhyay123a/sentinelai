"""Unit tests for the taint engine: provenance tracking and fact extraction."""
from __future__ import annotations

from agents.tools.base import ToolSpec
from gateway.taint.engine import TaintEngine

DOC = ToolSpec(name="document_read", reads_untrusted=True)
DB = ToolSpec(name="database_read", reads_sensitive=True)
HTTP = ToolSpec(name="http_request", is_external_sink=True)


def test_fresh_session_has_no_taint():
    engine = TaintEngine()
    facts = engine.facts_for("s1", HTTP, {"url": "x", "body": "y"})
    assert not facts.has_untrusted_ingest
    assert not facts.has_sensitive_access
    assert not facts.args_contain_sensitive_value


def test_untrusted_ingest_sets_flag():
    engine = TaintEngine()
    engine.observe_execution("s1", DOC, "some untrusted text")
    facts = engine.facts_for("s1", HTTP, {"url": "x", "body": "y"})
    assert facts.has_untrusted_ingest


def test_sensitive_access_is_recorded_and_matched_in_egress():
    engine = TaintEngine()
    engine.observe_execution("s1", DB, "sk-live-abc123SECRET")
    facts = engine.facts_for("s1", HTTP, {"body": "sk-live-abc123SECRET"})
    assert facts.has_sensitive_access
    assert facts.args_contain_sensitive_value


def test_sessions_are_isolated():
    engine = TaintEngine()
    engine.observe_execution("s1", DOC, "untrusted")
    facts_other = engine.facts_for("s2", HTTP, {"body": "z"})
    assert not facts_other.has_untrusted_ingest
