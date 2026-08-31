# Security Policy

## About this project

SentinelAI is a defensive security research project. It contains **intentionally
vulnerable demo agents and controlled attack scenarios** used to demonstrate and
test the gateway's containment of prompt-injection data exfiltration (the "lethal
trifecta"). These are deliberate, sandboxed test fixtures — not vulnerabilities in
SentinelAI itself.

All attack scenarios (`scenarios/`, `redteam/`) are designed to run only against
this project's own local, simulated agents and tools. No real network egress, real
credentials, or third-party systems are involved: the `http_request` tool simulates
egress and records it in memory rather than sending anything.

## Reporting a vulnerability

If you believe you have found a genuine security issue in SentinelAI's own code
(as opposed to the intentional demo fixtures described above), please report it
privately rather than opening a public issue:

- Open a GitHub **Security Advisory** on this repository, or
- Contact the maintainer directly via the email on their GitHub profile.

Please include a description, steps to reproduce, and the potential impact. I aim
to acknowledge reports within a few days.

## Scope

In scope: the gateway, taint engine, policy engine, risk engine, audit store, and
supporting code.

Out of scope: the intentionally vulnerable demo agents, the scripted attacks, and
the red-team probes — these are test fixtures and behave insecurely by design.
