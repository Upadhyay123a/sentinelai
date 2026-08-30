"""database_read tool — reads records, including sensitive secrets."""
from __future__ import annotations

from agents.tools.base import Tool, ToolSpec

_DATABASE = {
    "CUSTOMER_API_KEY": "sk-live-abc123SECRET",
    "company_name": "Acme Corp",
}


class DatabaseReadTool(Tool):
    spec = ToolSpec(name="database_read", reads_sensitive=True)

    def run(self, *, key: str) -> str:
        return _DATABASE.get(key, "")
