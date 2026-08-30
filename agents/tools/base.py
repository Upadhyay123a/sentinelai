"""Tool interface, capability tags, and the mediated ToolProxy (complete mediation)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gateway.orchestrator import Gateway


@dataclass(frozen=True)
class ToolSpec:
    """Declared capabilities of a tool, in lethal-trifecta terms."""

    name: str
    reads_untrusted: bool = False
    reads_sensitive: bool = False
    is_external_sink: bool = False


class Tool(ABC):
    spec: ToolSpec

    @abstractmethod
    def run(self, **kwargs: Any) -> Any:
        """Execute the REAL side effect. Only the gateway may call this."""
        ...


class ToolProxy:
    """The only tool handle an agent ever holds.

    The agent cannot reach Tool.run() directly. Every call is submitted to the
    gateway, which decides whether to execute the underlying tool.
    """

    def __init__(
        self, tool: Tool, gateway: "Gateway", session_id: str, agent_id: str
    ) -> None:
        self._tool = tool
        self._gateway = gateway
        self._session_id = session_id
        self._agent_id = agent_id

    @property
    def name(self) -> str:
        return self._tool.spec.name

    def __call__(self, **kwargs: Any) -> Any:
        return self._gateway.handle_tool_call(
            tool=self._tool,
            arguments=kwargs,
            session_id=self._session_id,
            agent_id=self._agent_id,
        )
