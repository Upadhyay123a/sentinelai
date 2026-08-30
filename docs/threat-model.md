# SentinelAI — Threat Model (Flagship Scenario)

## Scenario

An enterprise assistant agent can read documents, read a customer database, and
make HTTP requests. A user uploads a document and asks: *"Summarize this document."*
The document contains a hidden instruction planted by an attacker.

## Actors

| Actor | Role |
|-------|------|
| Attacker | Author of the uploaded document. Never touches the system directly — this is *indirect* injection. |
| Benign user | Asks for a summary in good faith; unaware of the payload. |
| Compromised agent | Executes the attacker's embedded instruction with the user's authority. |

## Assets

- The sensitive value `CUSTOMER_API_KEY` (stand-in for any secret / PII / record).
- The confidentiality boundary around private data generally.

## Trust boundaries

1. **Untrusted content → agent context.** The injection crosses here.
2. **Agent → tools.** *SentinelAI sits exactly on this boundary (the reference monitor).*
3. **Tools → external world.** Exfiltration would cross here.

## Attack path

Attacker embeds instructions in a document (crosses boundary 1) → the now-compromised
agent reads the secret and attempts to POST it out (attempts boundary 3). Mitigation:
boundary 2 is fully mediated, so the gateway sees the egress attempt, computes that
it carries sensitive data under untrusted influence, and blocks *before* boundary 3
is crossed.

## Why traditional app-sec does not catch this

There is no code vulnerability — no SQLi, XSS, or auth bypass. The malicious
instruction is data that became control. The agent behaves "correctly," just on
behalf of the wrong principal. Endpoint/API controls protect code paths, not agent
decisions.

## STRIDE mapping (abbreviated)

- **Information Disclosure** — the primary threat: exfiltration of secrets.
- **Elevation of Privilege** — the agent acts with the user's authority on attacker
  intent.
- **Tampering** — untrusted content tampers with the agent's effective instructions.

## Controls

| Control | Mechanism |
|---------|-----------|
| Complete mediation | `ToolProxy`; agent cannot reach a real tool directly |
| Provenance tracking | Taint engine flags untrusted ingest + sensitive access |
| Policy enforcement | `trifecta.yaml`, deny-overrides, evaluated on facts |
| Egress containment | BLOCK when trifecta legs converge on an external sink |
| Auditability | Append-only evidence chain for every decision |

## Residual risk / limitations

- The precise value-matcher is defeatable by encoding/transformation. Mitigation:
  the decision rests on the conservative context-flow rule instead.
- The conservative rule over-approximates and can produce false positives on
  legitimate "read untrusted thing, then call a legitimate external API" flows.
  Mitigation: use `REQUIRE_APPROVAL` for medium-confidence cases rather than BLOCK.
- Context-level taint is coarse; true token-level provenance inside the LLM is not
  achievable today. SentinelAI contains consequences at the tool boundary rather
  than tracing data inside the model.

## Framework references

OWASP Top 10 for LLM Applications 2025 (LLM01 Prompt Injection, LLM02 Sensitive
Information Disclosure); OWASP Top 10 for Agentic Applications; MITRE ATLAS
(exfiltration); NIST AI RMF for risk vocabulary.
