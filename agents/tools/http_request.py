"""http_request tool — sends an outbound HTTP request. An external sink."""
from __future__ import annotations

from agents.tools.base import Tool, ToolSpec

# Records what was 'sent' so the demo can prove whether exfiltration happened.
SENT_REQUESTS: list[dict] = []


class HttpRequestTool(Tool):
    spec = ToolSpec(name="http_request", is_external_sink=True)

    def run(self, *, url: str, body: str) -> str:
        # SIMULATED egress — we never make a real network call.
        SENT_REQUESTS.append({"url": url, "body": body})
        return f"POSTed {len(body)} bytes to {url}"
