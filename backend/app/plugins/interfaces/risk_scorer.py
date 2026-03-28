from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class RiskScorerPlugin(ABC):
    @abstractmethod
    async def calculate_risk_score(self, vulnerabilities: list[dict[str, Any]], business_context: dict[str, Any]) -> dict[str, Any]:
        """Calculate financial and operational impact score."""

    @abstractmethod
    async def generate_risk_report(self, risk_score: dict[str, Any]) -> dict[str, Any]:
        """Generate executive risk report output."""
