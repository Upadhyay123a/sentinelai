# SentinelAI

**A runtime security gateway for AI agents — lethal-trifecta containment.**

SentinelAI sits between an AI agent and its tools as a *reference monitor*: every
tool call is mediated, data provenance is tracked across the session, and a
deterministic policy engine decides `ALLOW` / `BLOCK` / `REQUIRE_APPROVAL` before
any dangerous action executes.

## The problem

AI agents combine three capabilities that are individually useful but lethal
together — Simon Willison's **"lethal trifecta"**:

1. **Access to private data** (databases, files, secrets)
2. **Exposure to untrusted content** (documents, web pages, emails)
3. **Ability to communicate externally** (HTTP, email)

When all three meet, a malicious instruction hidden in untrusted content can make
the agent read private data and send it to an attacker — *indirect prompt
injection leading to data exfiltration*. The agent isn't buggy; it's doing its job
for the wrong principal. Traditional app-sec (SQLi, XSS, auth) doesn't catch this,
because the exploit is language, not a code vulnerability.

You can't remove any leg without breaking the agent's usefulness — so SentinelAI
**contains** the trifecta at runtime instead of trying to prevent it.

## The core demo: same attack, gateway off vs on

**DISABLED (SentinelAI off)** — the attack succeeds:

**ENFORCE (SentinelAI on)** — the same attack is blocked at the egress step:

The block fires at the exact moment all three trifecta legs are present *and*
pointed at an external sink — not on the database read, which is legitimate.

## How it works

- **Complete mediation** — the agent holds only `ToolProxy` handles; there is no
  code path to a real tool that skips the gateway. We assume the agent is fully
  compromised and containment still holds. (Proved by `tests/test_mediation.py`.)
- **Deterministic decisions** — the verdict is a pure function of taint facts and
  YAML policy. No LLM in the decision path; same input → same output.
- **Enforcement modes** — `DISABLED` (baseline), `MONITOR` (detect only),
  `ENFORCE` (detect + block). Monitor and enforce run identical analysis.

## Run it

```bash
python -m pip install -e ".[dev]"   # or: pip install pyyaml pytest
python -m scenarios.flagship_exfil  # the OFF vs ON demo
python -m pytest -v                 # 14 tests: taint, policy, mediation, e2e
```

## Repository layout

| Path | Responsibility |
|------|----------------|
| `gateway/orchestrator.py` | The reference monitor — mediates every tool call |
| `gateway/taint/`   | Provenance tracking; produces taint facts (never decides) |
| `gateway/policy/`  | YAML policy-as-code + deny-overrides evaluation |
| `gateway/risk/`    | Deterministic scoring formula (advisory only) |
| `gateway/audit/`   | Append-only event store (evidence chain) |
| `agents/`          | Agent interface + a scripted compromised agent |
| `agents/tools/`    | Tools tagged with trifecta capabilities |
| `policies/`        | `trifecta.yaml` containment rules |
| `scenarios/`       | The flagship OFF-vs-ON demo |
| `tests/`           | Unit + mediation invariant + e2e acceptance |
| `docs/`            | Architecture and threat model |

## Framework alignment

Detections map to **OWASP Top 10 for LLM Applications (2025)** — LLM01 Prompt
Injection, LLM02 Sensitive Information Disclosure — the **OWASP Top 10 for Agentic
Applications**, and **MITRE ATLAS** exfiltration techniques.

## Status & limitations

MVP (M1–M2): flagship scenario, taint tracking, policy enforcement, tests. The
precise value-matcher can be evaded by encoding — which is why the *decision* rests
on the conservative context-flow rule (any egress after untrusted ingest +
sensitive access), accepting some false positives in exchange for not missing
attacks. Context-level taint is coarse because the LLM is opaque; true token-level
provenance inside the model isn't possible today.

See `docs/architecture.md` and `docs/threat-model.md` for the full reasoning.
