"""Tests for the red-team harness: each probe yields its expected secure outcome,
and the two detection rules cover each other's blind spots."""
from __future__ import annotations

from gateway.events import Decision
from redteam.runner import run_all

CONSERVATIVE = "no-sensitive-exfil-under-untrusted-influence"
PRECISE = "sensitive-value-in-egress"


def _by_id():
    return {f.probe.id: f for f in run_all()}


def test_all_probes_meet_expected_outcome():
    assert all(f.passed for f in run_all())


def test_no_false_negatives_or_positives():
    klasses = [f.klass for f in run_all()]
    assert "FN" not in klasses  # no attack got through
    assert "FP" not in klasses  # no benign call was blocked


def test_direct_exfil_trips_both_rules():
    f = _by_id()["RT-001"]
    assert f.actual == Decision.BLOCK
    assert CONSERVATIVE in f.matched_policies
    assert PRECISE in f.matched_policies


def test_encoded_exfil_caught_by_conservative_rule_only():
    f = _by_id()["RT-002"]
    assert f.actual == Decision.BLOCK
    assert CONSERVATIVE in f.matched_policies
    assert PRECISE not in f.matched_policies  # exact-match evaded by encoding


def test_no_untrusted_exfil_caught_by_precise_rule_only():
    f = _by_id()["RT-003"]
    assert f.actual == Decision.BLOCK
    assert PRECISE in f.matched_policies
    assert CONSERVATIVE not in f.matched_policies  # no untrusted leg present


def test_benign_external_is_allowed():
    f = _by_id()["RT-004"]
    assert f.actual == Decision.ALLOW
    assert f.matched_policies == []
