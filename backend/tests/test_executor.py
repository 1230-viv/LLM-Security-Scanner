from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from app.schemas.attack import AttackExecutionResult, AttackPrompt
from app.services.executor import AttackExecutor, TargetExecutionConfig


def _prompt(prompt_id: str) -> AttackPrompt:
    return AttackPrompt(
        id=prompt_id,
        category="instruction_override",
        prompt_text=f"prompt-{prompt_id}",
        description="test",
        severity="low",
        metadata={},
    )


def _target() -> TargetExecutionConfig:
    return TargetExecutionConfig(
        endpoint_url="http://example.invalid",
        api_key=None,
        request_template={"prompt": "{prompt}"},
        headers={},
        timeout=5,
    )


class FakeExecutor(AttackExecutor):
    def __init__(self, delays: dict[str, float], *, max_concurrent_requests: int) -> None:
        super().__init__(
            max_concurrent_requests=max_concurrent_requests,
            requests_per_second=10000,
            timeout=5,
        )
        self._delays = delays

    async def execute_prompt(
        self,
        client: Any,
        prompt: AttackPrompt,
        target: TargetExecutionConfig,
    ) -> AttackExecutionResult:
        await asyncio.sleep(self._delays.get(prompt.id, 0.001))
        return AttackExecutionResult(
            prompt_id=prompt.id,
            prompt_text=prompt.prompt_text,
            request_payload={"prompt": prompt.prompt_text},
            response_payload={"ok": True},
            status_code=200,
            response_time_ms=1,
            timestamp=datetime.now(timezone.utc),
            error=None,
            token_estimate=10,
            cost_estimate=0.0,
        )


def test_execute_batch_stream_yields_all_results() -> None:
    executor = FakeExecutor(delays={}, max_concurrent_requests=4)
    prompts = [_prompt(f"p{i}") for i in range(8)]

    async def _run() -> list[AttackExecutionResult]:
        results = []
        async for result in executor.execute_batch_stream(prompts=prompts, target=_target()):
            results.append(result)
        return results

    results = asyncio.run(_run())

    assert len(results) == len(prompts)
    assert {item.prompt_id for item in results} == {prompt.id for prompt in prompts}


def test_execute_batch_stream_returns_completed_results_first() -> None:
    executor = FakeExecutor(delays={"slow": 0.05, "fast": 0.001}, max_concurrent_requests=2)
    prompts = [_prompt("slow"), _prompt("fast")]

    async def _run() -> list[str]:
        ordered_ids: list[str] = []
        async for result in executor.execute_batch_stream(prompts=prompts, target=_target()):
            ordered_ids.append(result.prompt_id)
        return ordered_ids

    ordered_ids = asyncio.run(_run())

    assert ordered_ids[0] == "fast"
    assert set(ordered_ids) == {"fast", "slow"}
