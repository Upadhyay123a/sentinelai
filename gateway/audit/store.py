"""Append-only audit store for SecurityEvents (in-memory implementation for M1)."""
from __future__ import annotations

from abc import ABC, abstractmethod

from gateway.events import SecurityEvent


class AuditStore(ABC):
    @abstractmethod
    def append(self, event: SecurityEvent) -> None: ...

    @abstractmethod
    def by_session(self, session_id: str) -> list[SecurityEvent]: ...

    @abstractmethod
    def all(self) -> list[SecurityEvent]: ...


class InMemoryAuditStore(AuditStore):
    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []

    def append(self, event: SecurityEvent) -> None:
        # append-only: we never mutate or delete existing events
        self._events.append(event)

    def by_session(self, session_id: str) -> list[SecurityEvent]:
        return [e for e in self._events if e.session_id == session_id]

    def all(self) -> list[SecurityEvent]:
        return list(self._events)
