"""Tests for the SQLite audit store: round-trip fidelity, ordering, durability."""
from __future__ import annotations

from gateway.audit.sqlite_store import SqliteAuditStore
from gateway.events import Decision, EventType, SecurityEvent, Severity


def test_append_and_read_round_trip(tmp_path):
    store = SqliteAuditStore(tmp_path / "t.db")
    store.append(SecurityEvent(
        session_id="s1", type=EventType.POLICY_DECISION, tool="http_request",
        arguments={"url": "x", "body": "y"}, decision=Decision.BLOCK,
        matched_policies=["rule-a", "rule-b"], severity=Severity.CRITICAL,
        risk_score=95, evidence=["e1", "e2"], references=["OWASP-LLM01"],
    ))
    r = store.by_session("s1")[0]
    assert r.decision == Decision.BLOCK
    assert r.severity == Severity.CRITICAL
    assert r.matched_policies == ["rule-a", "rule-b"]
    assert r.arguments == {"url": "x", "body": "y"}
    assert r.risk_score == 95
    assert r.references == ["OWASP-LLM01"]


def test_none_enums_survive(tmp_path):
    store = SqliteAuditStore(tmp_path / "t.db")
    store.append(SecurityEvent(session_id="s1", type=EventType.AGENT_INVOCATION))
    r = store.by_session("s1")[0]
    assert r.decision is None
    assert r.severity is None


def test_insertion_order_preserved(tmp_path):
    store = SqliteAuditStore(tmp_path / "t.db")
    for i in range(5):
        store.append(SecurityEvent(
            session_id="s1", type=EventType.TOOL_EXECUTED, tool=f"t{i}"))
    assert [e.tool for e in store.by_session("s1")] == ["t0", "t1", "t2", "t3", "t4"]


def test_sessions_isolated(tmp_path):
    store = SqliteAuditStore(tmp_path / "t.db")
    store.append(SecurityEvent(session_id="s1", type=EventType.AGENT_INVOCATION))
    store.append(SecurityEvent(session_id="s2", type=EventType.AGENT_INVOCATION))
    assert len(store.by_session("s1")) == 1
    assert len(store.all()) == 2
    assert set(store.sessions()) == {"s1", "s2"}


def test_persists_across_reopen(tmp_path):
    path = tmp_path / "persist.db"
    SqliteAuditStore(path).append(
        SecurityEvent(session_id="s1", type=EventType.AGENT_INVOCATION))
    # a brand-new connection to the same file still sees the event
    assert len(SqliteAuditStore(path).by_session("s1")) == 1
