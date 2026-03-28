from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.attack import AttackExecutionResult, Vulnerability


class DetectorPlugin(ABC):
    name: str
    vulnerability_type: str
    supported_categories: set[str]

    @abstractmethod
    async def detect(self, response: AttackExecutionResult) -> list[Vulnerability]:
        """Detect vulnerabilities from a single attack response."""
