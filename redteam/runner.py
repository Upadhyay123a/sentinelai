"""Red-team harness: run every probe through the gateway (ENFORCE) and score it.

    python -m redteam.runner

Reports a findings table plus a confusion matrix (TP/FN/TN/FP). A false negative
(FN) means an attack got through -- the outcome a security team cares about most.
Exits non-zero if any attack succeeds or any benign call is blocked (CI-friendly).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Mapping

from agents.base import Agent
from agents.tools.base import ToolProxy
from agents.tools.database_read import DatabaseReadTool
from agents.tools.document_read import DocumentReadTool
from agents.tools.http_request import SENT_REQUESTS, HttpRequestTool
from gateway.audit.store import InMemoryAuditStore
from gateway.config import EnforcementMode, GatewayConfig
from gateway.events import Decision
from gateway.orchestrator import Gateway
from gateway.policy.engine import PolicyEngine
from gateway.taint.engine import TaintEngine
from redteam.detector import enforced_outcome
from redteam.probes import PROBES, Probe

POLICY_PATH = "policies/trifecta.yaml"


class ProbeAgent(Agent):
    """Adapts a probe's attack callable to the Agent interface."""

    def __init__(self, probe: Probe) -> None:
        self.agent_id = f"probe:{probe.id}"
        self._probe = probe

    def run(self, prompt: str, tools: Mapping[str, ToolProxy]) -> str:
        self._probe.attack(tools)
        return f"{self._probe.id} complete"


@dataclass
class Finding:
    probe: Probe
    actual: Decision
    matched_policies: list[str]

    @property
    def klass(self) -> str:
        exp, act = self.probe.expected, self.actual
        if exp == Decision.BLOCK and act == Decision.BLOCK:
            return "TP"
        if exp == Decision.BLOCK and act == Decision.ALLOW:
            return "FN"
        if exp == Decision.ALLOW and act == Decision.ALLOW:
            return "TN"
        return "FP"

    @property
    def passed(self) -> bool:
        return self.actual == self.probe.expected


def run_probe(probe: Probe) -> Finding:
    SENT_REQUESTS.clear()
    audit = InMemoryAuditStore()
    gateway = Gateway(
        config=GatewayConfig(mode=EnforcementMode.ENFORCE),
        audit=audit,
        tools=[DocumentReadTool(), DatabaseReadTool(), HttpRequestTool()],
        taint=TaintEngine(),
        policy=PolicyEngine.from_yaml(POLICY_PATH),
    )
    sid = str(uuid.uuid4())
    gateway.run_agent(ProbeAgent(probe), "run probe", sid)
    actual, policies = enforced_outcome(audit.by_session(sid))
    return Finding(probe=probe, actual=actual, matched_policies=policies)


def run_all() -> list[Finding]:
    return [run_probe(p) for p in PROBES]


def _report(findings: list[Finding]) -> None:
    print("SentinelAI red-team run (ENFORCE)\n")
    print(f"{'PROBE':7} {'CATEGORY':20} {'EXPECT':6} {'ACTUAL':6} {'':4} POLICIES")
    print("-" * 78)
    for f in findings:
        mark = "PASS" if f.passed else "FAIL"
        pol = ",".join(f.matched_policies) or "-"
        print(f"{f.probe.id:7} {f.probe.category:20} "
              f"{f.probe.expected.value:6} {f.actual.value:6} {mark:4} {pol}")

    tally = {"TP": 0, "FN": 0, "TN": 0, "FP": 0}
    for f in findings:
        tally[f.klass] += 1
    attacks = tally["TP"] + tally["FN"]
    benign = tally["TN"] + tally["FP"]
    print("\nConfusion matrix:")
    print(f"  attacks blocked (TP):  {tally['TP']}/{attacks}")
    print(f"  attacks missed  (FN):  {tally['FN']}/{attacks}   <- dangerous")
    print(f"  benign allowed  (TN):  {tally['TN']}/{benign}")
    print(f"  benign blocked  (FP):  {tally['FP']}/{benign}   <- false alarms")
    asr = (tally["FN"] / attacks) if attacks else 0.0
    print(f"\nAttack success rate (attacker's view): {asr:.0%}")


def main() -> int:
    findings = run_all()
    _report(findings)
    return 0 if all(f.passed for f in findings) else 1


if __name__ == "__main__":
    raise SystemExit(main())
