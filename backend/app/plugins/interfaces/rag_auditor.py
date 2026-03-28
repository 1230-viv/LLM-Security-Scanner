from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class RAGAuditorPlugin(ABC):
    @abstractmethod
    async def audit_retrieval(self, query: str, retrieved_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Audit retrieval stage for security issues."""

    @abstractmethod
    async def audit_generation(self, context: str, generated_response: str) -> list[dict[str, Any]]:
        """Audit generation stage for leakage and poisoning risks."""
