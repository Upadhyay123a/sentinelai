# SentinelAI

**A runtime security gateway for AI agents — it stops an AI agent from being
tricked into leaking your data.**

![SentinelAI demo: the same attack leaks a secret with the gateway off, and is blocked with it on](docs/demo.gif)

In 2025–2026, production AI assistants were repeatedly tricked into exfiltrating
private data by instructions hidden inside ordinary content — a document, an email,
a support ticket. In one five-day stretch in January 2026, four shipped products
were exploited by the same pattern. The agent wasn't hacked in the traditional
sense; it followed a malicious instruction it couldn't tell apart from its real
task, using its own legitimate access. SentinelAI is a control that **contains**
that attack at runtime: it sits between the agent and its tools, tracks where data
came from, and blocks the dangerous combination before anything leaves.

---

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

## How it works

```mermaid
flowchart TB
    U["User prompt + untrusted document"] --> A["Agent Runtime<br/>holds only ToolProxy handles"]
    A -->|"tool call (no direct access)"| GW
    subgraph GW["SentinelAI Gateway — Reference Monitor"]
        direction TB
        T["Taint Engine<br/>produces facts, never decides"] --> R["Risk Engine<br/>score + band (advisory)"]
        R --> P["Policy Engine<br/>facts + YAML rules -> decision"]
        P --> AU["Audit Store<br/>append-only evidence"]
    end
    GW -->|ALLOW| TOOLS["Real Tools<br/>document_read - database_read - http_request"]
    GW -->|BLOCK| STOP["Blocked — nothing executes,<br/>evidence recorded"]
    TOOLS --> EXT["External world / egress"]
```

- **Complete mediation** — the agent holds only `ToolProxy` handles; there is no
  code path to a real tool that skips the gateway. We assume the agent is fully
  compromised and containment still holds. (Proved by `tests/test_mediation.py`.)
- **Deterministic decisions** — the verdict is a pure function of taint facts and
  YAML policy. No LLM in the decision path; same input -> same output.
- **Enforcement modes** — `DISABLED` (baseline), `MONITOR` (detect only),
  `ENFORCE` (detect + block). Monitor and enforce run identical analysis.

## The core demo: same attack, gateway off vs on

```
python -m scenarios.demo            # full narrated demo (used for the GIF above)
python -m scenarios.flagship_exfil  # just the OFF vs ON contrast
```

**DISABLED (SentinelAI off)** — the attack succeeds:

```
tool_executed   http_request   decision=ALLOW
[!] EXFILTRATION SUCCEEDED -> https://attacker.example/collect leaked: sk-live-abc123SECRET
```

**ENFORCE (SentinelAI on)** — the same attack is blocked at the egress step:

```
policy_decision http_request   decision=BLOCK policy=no-sensitive-exfil-under-untrusted-influence risk=95
tool_blocked    http_request   decision=BLOCK
[OK] No data left the boundary.
    BLOCKED http_request: CRITICAL risk=95
    refs=OWASP-LLM01,OWASP-LLM02,ATLAS-Exfiltration  evidence=8 prior events
```

The block fires at the exact moment all three trifecta legs are present *and*
pointed at an external sink — not on the database read, which is legitimate.

## Red-team validation

A probe/detector/harness red-team runner (modeled on garak / PyRIT) fires four
attack variants and scores them into a confusion matrix — **zero false negatives,
zero false positives**, including an encoded-secret payload that evades exact-match
detection but is still caught by the conservative data-flow rule. See
[`docs/redteam.md`](docs/redteam.md).

```
python -m redteam.runner
```

## Run it

```bash
python -m pip install -e ".[dev]"   # or: pip install pyyaml pytest
python -m scenarios.demo            # narrated end-to-end demo
python -m scenarios.flagship_exfil  # the OFF vs ON demo
python -m scenarios.persist_demo    # run an incident into the SQLite audit store
python -m redteam.runner            # red-team harness + confusion matrix
python -m pytest -v                 # 25 tests: taint, policy, mediation, audit, redteam, e2e
```

## Repository layout

| Path | Responsibility |
|------|----------------|
| `gateway/orchestrator.py` | The reference monitor — mediates every tool call |
| `gateway/taint/`   | Provenance tracking; produces taint facts (never decides) |
| `gateway/policy/`  | YAML policy-as-code + deny-overrides evaluation |
| `gateway/risk/`    | Deterministic scoring formula (advisory only) |
| `gateway/audit/`   | Append-only event store (in-memory + SQLite) + read-only viewer |
| `agents/`          | Agent interface + a scripted compromised agent |
| `agents/tools/`    | Tools tagged with trifecta capabilities |
| `redteam/`         | Probe/detector/harness red-team runner |
| `policies/`        | `trifecta.yaml` containment rules |
| `scenarios/`       | Flagship OFF-vs-ON demo, persistence demo, narrated demo |
| `tests/`           | Unit + mediation invariant + audit + red-team + e2e |
| `docs/`            | Architecture, threat model, red-team results |

## Roadmap

```mermaid
flowchart LR
    subgraph DONE["Built"]
        direction TB
        M1["M1 - Gateway pass-through<br/>flagship attack succeeds"]
        M2["M2 - Taint + Policy + Risk<br/>ENFORCE blocks exfil"]
        M3["M3 - Persistent SQLite audit<br/>+ read-only incident viewer"]
        M4["M4 - Red-team harness<br/>confusion matrix, 0 FN / 0 FP"]
        M1 --> M2 --> M3 --> M4
    end
    subgraph NEXT["Planned"]
        direction TB
        M5["M5 - ML supporting signal<br/>(honestly evaluated)"]
        M6["M6 - RAG poisoning + DLP<br/>+ hardening"]
        M5 --> M6
    end
    M4 --> M5
```

## Framework alignment

Detections map to **OWASP Top 10 for LLM Applications (2025)** — LLM01 Prompt
Injection, LLM02 Sensitive Information Disclosure — the **OWASP Top 10 for Agentic
Applications**, and **MITRE ATLAS** exfiltration techniques.

## Status & limitations

Built through M4: flagship scenario, taint tracking, policy enforcement, persistent
audit + incident viewer, red-team harness, 25 tests. The precise value-matcher can
be evaded by encoding — which is why the *decision* rests on the conservative
context-flow rule (any egress after untrusted ingest + sensitive access), accepting
some false positives in exchange for not missing attacks. Context-level taint is
coarse because the LLM is opaque; true token-level provenance inside the model isn't
possible today.

See `docs/architecture.md`, `docs/threat-model.md`, and `docs/redteam.md` for the
full reasoning.
