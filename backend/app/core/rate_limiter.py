from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque


class InMemoryRateLimiter:
    """Simple per-client rolling-window rate limiter for API requests."""

    def __init__(self, requests_per_minute: int) -> None:
        self.requests_per_minute = max(1, requests_per_minute)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def allow(self, client_id: str) -> bool:
        now = time.time()
        window_start = now - 60

        async with self._lock:
            queue = self._events[client_id]
            while queue and queue[0] < window_start:
                queue.popleft()

            if len(queue) >= self.requests_per_minute:
                return False

            queue.append(now)
            return True
