from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class CompliancePlugin(ABC):
    @abstractmethod
    async def assess_compliance(self, scan_result: dict[str, Any], framework: str) -> dict[str, Any]:
        """Evaluate scan result against target compliance framework."""

    @abstractmethod
    async def generate_audit_trail(self, scans: list[dict[str, Any]], time_period: dict[str, str]) -> dict[str, Any]:
        """Generate a machine-readable audit trail."""
