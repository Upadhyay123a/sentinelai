"""Provenance / taint engine: tracks per-session data flow and emits taint facts.

Design note: this engine ONLY produces facts. It never decides ALLOW/BLOCK — that
belongs to the policy engine. Keeping analysis and decision separate makes each
independently testable and keeps enforcement logic in one place (the policy).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.tools.base import ToolSpec


@dataclass
class SessionProvenance:
    has_untrusted_ingest: bool = False
    has_sensitive_access: bool = False
    sensitive_values: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class TaintFacts:
    tool: str
    is_external_sink: bool
    args_contain_sensitive_value: bool
    has_untrusted_ingest: bool
    has_sensitive_access: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "call.tool": self.tool,
            "call.is_external_sink": self.is_external_sink,
            "call.args_contain_sensitive_value": self.args_contain_sensitive_value,
            "session.has_untrusted_ingest": self.has_untrusted_ingest,
            "session.has_sensitive_access": self.has_sensitive_access,
        }


class TaintEngine:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionProvenance] = {}

    def _session(self, session_id: str) -> SessionProvenance:
        return self._sessions.setdefault(session_id, SessionProvenance())

    def facts_for(
        self, session_id: str, spec: ToolSpec, arguments: dict[str, Any]
    ) -> TaintFacts:
        """Compute taint facts for a PENDING tool call (before execution)."""
        prov = self._session(session_id)
        return TaintFacts(
            tool=spec.name,
            is_external_sink=spec.is_external_sink,
            args_contain_sensitive_value=self._args_contain_sensitive(prov, arguments),
            has_untrusted_ingest=prov.has_untrusted_ingest,
            has_sensitive_access=prov.has_sensitive_access,
        )

    def observe_execution(self, session_id: str, spec: ToolSpec, result: Any) -> None:
        """Update session provenance AFTER a tool actually executed."""
        prov = self._session(session_id)
        if spec.reads_untrusted:
            prov.has_untrusted_ingest = True
        if spec.reads_sensitive:
            prov.has_sensitive_access = True
            value = str(result).strip()
            if value:
                prov.sensitive_values.add(value)

    @staticmethod
    def _args_contain_sensitive(
        prov: SessionProvenance, arguments: dict[str, Any]
    ) -> bool:
        # Simple substring match — proves exfiltration of a KNOWN secret. It is
        # deliberately NOT robust to encoding/obfuscation (a documented limit);
        # the conservative context-flow policy rule covers that evasion gap.
        haystack = " ".join(str(v) for v in arguments.values())
        return any(secret in haystack for secret in prov.sensitive_values)
