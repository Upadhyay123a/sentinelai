"""Read-only viewer for the persistent audit store.

    python -m gateway.audit.view <db>              # list all sessions + outcome
    python -m gateway.audit.view <db> <session_id> # full trail for one session

This module only reads. It is the 'show me a past incident' answer.
"""
from __future__ import annotations

import sys

from gateway.audit.sqlite_store import SqliteAuditStore
from gateway.events import EventType


def _summarize(store: SqliteAuditStore) -> None:
    sessions = store.sessions()
    if not sessions:
        print("No sessions recorded.")
        return
    print(f"{len(sessions)} session(s) recorded:\n")
    for sid in sessions:
        events = store.by_session(sid)
        blocked = [e for e in events if e.type == EventType.TOOL_BLOCKED]
        outcome = "BLOCKED" if blocked else "allowed"
        sev = blocked[0].severity.value if blocked and blocked[0].severity else ""
        print(f"  {sid}  events={len(events):2d}  outcome={outcome} {sev}")
    print("\nRun again with a session id to see its full trail.")


def _detail(store: SqliteAuditStore, session_id: str) -> None:
    events = store.by_session(session_id)
    if not events:
        print(f"No events for session {session_id}")
        return
    print(f"Trail for session {session_id}:\n")
    for e in events:
        line = f"  {e.timestamp}  {e.type.value:22} {e.tool or '':14}"
        if e.decision:
            line += f" {e.decision.value}"
        if e.matched_policies:
            line += f" [{','.join(e.matched_policies)}]"
        print(line)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python -m gateway.audit.view <db> [session_id]")
        return 1
    store = SqliteAuditStore(argv[1])
    if len(argv) >= 3:
        _detail(store, argv[2])
    else:
        _summarize(store)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
