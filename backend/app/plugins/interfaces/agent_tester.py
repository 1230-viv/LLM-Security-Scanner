from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class AgentTesterPlugin(ABC):
    @abstractmethod
    async def test_tool_usage(self, agent: dict[str, Any], attack_scenarios: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Test agent tool access and misuse scenarios."""

    @abstractmethod
    async def test_planning(self, agent: dict[str, Any], malicious_goals: list[str]) -> list[dict[str, Any]]:
        """Test plan-level safety and goal hijacking resistance."""
