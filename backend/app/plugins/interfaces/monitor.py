from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any


class MonitorPlugin(ABC):
    @abstractmethod
    async def monitor_endpoint(self, endpoint: str, interval_seconds: int) -> AsyncIterator[dict[str, Any]]:
        """Continuously monitor endpoint behavior for regression and anomalies."""

    @abstractmethod
    async def alert(self, event: dict[str, Any], severity: str) -> None:
        """Emit monitoring alerts."""
