"""Agent interface. Agents receive only ToolProxy handles, never real tools."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Mapping

from agents.tools.base import ToolProxy


class Agent(ABC):
    agent_id: str

    @abstractmethod
    def run(self, prompt: str, tools: Mapping[str, ToolProxy]) -> str: ...
