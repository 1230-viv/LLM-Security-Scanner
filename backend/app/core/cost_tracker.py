from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ResourceUsage:
    total_requests: int = 0
    total_tokens: int = 0
    total_cost: float = 0.0


class CostTracker:
    """Tracks scan resource usage and enforces configured limits."""

    def __init__(self) -> None:
        self.usage = ResourceUsage()

    def track_request(self, tokens_used: int, cost: float) -> None:
        self.usage.total_requests += 1
        self.usage.total_tokens += max(0, tokens_used)
        self.usage.total_cost += max(0.0, cost)

    def check_limits(
        self,
        max_requests: int | None,
        max_tokens: int | None,
        cost_limit: float | None,
    ) -> bool:
        if max_requests is not None and self.usage.total_requests >= max_requests:
            return False
        if max_tokens is not None and self.usage.total_tokens >= max_tokens:
            return False
        if cost_limit is not None and self.usage.total_cost >= cost_limit:
            return False
        return True
