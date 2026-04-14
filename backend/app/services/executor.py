from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from app.schemas.attack import AttackExecutionResult, AttackPrompt


@dataclass
class TargetExecutionConfig:
    endpoint_url: str
    api_key: str | None
    request_template: dict[str, Any]
    headers: dict[str, str]
    timeout: int


class AsyncRequestRateLimiter:
    def __init__(self, requests_per_second: float) -> None:
        self.interval = 1.0 / max(requests_per_second, 0.01)
        self._next_allowed = 0.0
        self._lock = asyncio.Lock()

    async def wait_turn(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait_for = self._next_allowed - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            now = time.monotonic()
            self._next_allowed = now + self.interval


class AttackExecutor:
    """Executes attack prompts against a configured endpoint."""

    def __init__(
        self,
        max_concurrent_requests: int,
        requests_per_second: float,
        timeout: int,
    ) -> None:
        self._max_concurrent_requests = max_concurrent_requests
        self._semaphore = asyncio.Semaphore(max_concurrent_requests)
        self._rate_limiter = AsyncRequestRateLimiter(requests_per_second)
        self._timeout = timeout

    def _http_limits(self) -> httpx.Limits:
        max_connections = max(self._max_concurrent_requests * 2, 20)
        max_keepalive = max(self._max_concurrent_requests, 10)
        return httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive,
        )

    async def execute_prompt(
        self,
        client: httpx.AsyncClient,
        prompt: AttackPrompt,
        target: TargetExecutionConfig,
    ) -> AttackExecutionResult:
        await self._rate_limiter.wait_turn()

        async with self._semaphore:
            payload = _inject_prompt(target.request_template, prompt.prompt_text)
            headers = dict(target.headers)
            if target.api_key and "authorization" not in {key.lower() for key in headers}:
                headers["Authorization"] = f"Bearer {target.api_key}"

            started = time.perf_counter()
            try:
                response = await client.post(
                    target.endpoint_url,
                    json=payload,
                    headers=headers,
                    timeout=target.timeout or self._timeout,
                )
                elapsed_ms = int((time.perf_counter() - started) * 1000)

                response_payload: dict[str, Any]
                try:
                    response_payload = response.json()
                except json.JSONDecodeError:
                    response_payload = {"raw_text": response.text}

                token_estimate = _estimate_tokens(response_payload)
                cost_estimate = round(token_estimate * 0.000002, 6)

                return AttackExecutionResult(
                    prompt_id=prompt.id,
                    prompt_text=prompt.prompt_text,
                    request_payload=payload,
                    response_payload=response_payload,
                    status_code=response.status_code,
                    response_time_ms=elapsed_ms,
                    timestamp=datetime.now(timezone.utc),
                    error=None,
                    token_estimate=token_estimate,
                    cost_estimate=cost_estimate,
                )
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return AttackExecutionResult(
                    prompt_id=prompt.id,
                    prompt_text=prompt.prompt_text,
                    request_payload=payload,
                    response_payload=None,
                    status_code=None,
                    response_time_ms=elapsed_ms,
                    timestamp=datetime.now(timezone.utc),
                    error=str(exc),
                    token_estimate=0,
                    cost_estimate=0.0,
                )

    async def execute_batch(
        self,
        prompts: list[AttackPrompt],
        target: TargetExecutionConfig,
    ) -> list[AttackExecutionResult]:
        async with httpx.AsyncClient(limits=self._http_limits()) as client:
            tasks = [self.execute_prompt(client, prompt, target) for prompt in prompts]
            return await asyncio.gather(*tasks)

    async def execute_batch_stream(
        self,
        prompts: list[AttackPrompt],
        target: TargetExecutionConfig,
    ) -> AsyncIterator[AttackExecutionResult]:
        async with httpx.AsyncClient(limits=self._http_limits()) as client:
            tasks = [
                asyncio.create_task(self.execute_prompt(client, prompt, target))
                for prompt in prompts
            ]

            try:
                for task in asyncio.as_completed(tasks):
                    yield await task
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)


def _inject_prompt(template: Any, prompt_text: str) -> Any:
    if isinstance(template, dict):
        return {key: _inject_prompt(value, prompt_text) for key, value in template.items()}
    if isinstance(template, list):
        return [_inject_prompt(item, prompt_text) for item in template]
    if isinstance(template, str):
        return template.replace("{prompt}", prompt_text)
    return template


def _estimate_tokens(response_payload: dict[str, Any]) -> int:
    raw = json.dumps(response_payload)
    return max(1, len(raw) // 4)
