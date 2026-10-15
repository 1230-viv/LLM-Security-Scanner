from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.response_processing import extract_response_text
from app.detectors.response_integrity import extract_and_decode_base64_payloads
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
            # Independently decode any Base64 test payload before dispatching
            b64_pairs = extract_and_decode_base64_payloads(
                prompt.prompt_text,
                trailing_punctuation_is_formatting=bool(
                    prompt.metadata.get("base64_trailing_punctuation_is_formatting")
                ),
            )
            test_metadata: dict[str, Any] = dict(prompt.metadata)
            test_metadata.setdefault("test_case_id", prompt.id)
            if b64_pairs:
                test_metadata["base64_payloads"] = [
                    {
                        "token": token,
                        "decoded": decoded,
                        "expected_plaintext": decoded,
                    }
                    for token, decoded in b64_pairs
                ]
                test_metadata["decoded_instruction"] = b64_pairs[0][1]
                test_metadata["expected_plaintext"] = b64_pairs[0][1]
            if prompt.expected_secure_behavior:
                test_metadata["expected_secure_behavior"] = prompt.expected_secure_behavior
            if prompt.success_criterion:
                test_metadata["success_criterion"] = prompt.success_criterion
            if prompt.security_property:
                test_metadata["security_property"] = prompt.security_property

            active_canaries = []
            if (
                isinstance(prompt.prerequisites, dict)
                and "synthetic_secrets" in prompt.prerequisites
            ):
                active_canaries = list(prompt.prerequisites["synthetic_secrets"])

            payload = _inject_prompt(target.request_template, prompt.prompt_text)
            payload = _inject_canary_context(payload, active_canaries)
            payload = _default_non_streaming_payload(target.endpoint_url, payload)
            headers = dict(target.headers)
            if target.api_key and "authorization" not in {key.lower() for key in headers}:
                headers["Authorization"] = "Bearer " + target.api_key

            started = time.perf_counter()
            try:
                response = await asyncio.wait_for(
                    client.post(
                        target.endpoint_url,
                        json=payload,
                        headers=headers,
                        timeout=target.timeout or self._timeout,
                    ),
                    timeout=(target.timeout or self._timeout) + 5,
                )
                elapsed_ms = int((time.perf_counter() - started) * 1000)

                response_payload: dict[str, Any]
                malformed_json = False
                try:
                    response_payload = response.json()
                except json.JSONDecodeError:
                    response_payload = {"raw_text": response.text}
                    malformed_json = True
                if not isinstance(response_payload, dict):
                    response_payload = {"raw_payload": response_payload}

                completion_metadata = _completion_metadata(response_payload)
                response_text = extract_response_text(response_payload)
                error_type = None
                outcome = "COMPLETED"
                error = None
                if response.status_code >= 400:
                    error_type = "provider_http_error"
                    outcome = "INCONCLUSIVE"
                    error = f"Provider returned HTTP {response.status_code}"
                elif malformed_json or not response_text:
                    error_type = "malformed_response"
                    outcome = "INCONCLUSIVE"
                    error = (
                        "Provider response was not valid JSON"
                        if malformed_json
                        else "Provider response did not contain usable response text"
                    )
                elif completion_metadata.get("complete") is False:
                    error_type = "incomplete_response"
                    outcome = "INCONCLUSIVE"
                    error = completion_metadata.get("reason")

                token_estimate = _estimate_tokens(response_payload)
                cost_estimate = round(token_estimate * 0.000002, 6)

                return AttackExecutionResult(
                    prompt_id=prompt.id,
                    test_case_id=prompt.id,
                    prompt_text=prompt.prompt_text,
                    request_payload=payload,
                    response_payload=response_payload,
                    status_code=response.status_code,
                    response_time_ms=elapsed_ms,
                    timestamp=datetime.now(UTC),
                    error=error,
                    error_type=error_type,
                    outcome=outcome,
                    completion_metadata=completion_metadata,
                    token_estimate=token_estimate,
                    cost_estimate=cost_estimate,
                    active_canaries=active_canaries,
                    test_metadata=test_metadata,
                )
            except httpx.TimeoutException as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _provider_error_result(
                    prompt, payload, active_canaries, elapsed_ms, "provider_timeout", exc
                )
            except TimeoutError as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _provider_error_result(
                    prompt, payload, active_canaries, elapsed_ms, "provider_timeout", exc
                )
            except httpx.RequestError as exc:
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _provider_error_result(
                    prompt, payload, active_canaries, elapsed_ms, "provider_connection_error", exc
                )
            except Exception as exc:  # noqa: BLE001
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return _provider_error_result(
                    prompt,
                    payload,
                    active_canaries,
                    elapsed_ms,
                    "provider_error",
                    exc,
                    test_metadata,
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


def _default_non_streaming_payload(endpoint_url: str, payload: Any) -> Any:
    """Make Ollama calls finite unless the caller explicitly selected streaming."""
    if not endpoint_url.rstrip("/").endswith(("/api/chat", "/api/generate")):
        return payload
    if isinstance(payload, dict) and "stream" not in payload:
        return {**payload, "stream": False}
    return payload


def _completion_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("done") is False or payload.get("complete") is False:
        return {"complete": False, "reason": "provider_reported_incomplete"}
    if payload.get("done") is True or payload.get("complete") is True:
        return {"complete": True}
    done_reason = payload.get("done_reason")
    if done_reason in {"length", "max_tokens", "timeout", "cancelled"}:
        return {"complete": False, "reason": f"done_reason:{done_reason}"}
    choices = payload.get("choices")
    if isinstance(choices, list):
        reasons = {
            choice.get("finish_reason")
            for choice in choices
            if isinstance(choice, dict) and choice.get("finish_reason") is not None
        }
        if reasons.intersection({"length", "max_tokens", "timeout", "cancelled"}):
            return {
                "complete": False,
                "reason": "choice_finish_reason:" + ",".join(sorted(reasons)),
            }
        if reasons:
            return {"complete": True, "finish_reason": ",".join(sorted(reasons))}
    return {"complete": None}


def _provider_error_result(
    prompt: AttackPrompt,
    payload: dict[str, Any],
    active_canaries: list[str],
    elapsed_ms: int,
    error_type: str,
    error: Exception,
    test_metadata: dict[str, Any] | None = None,
) -> AttackExecutionResult:
    return AttackExecutionResult(
        prompt_id=prompt.id,
        test_case_id=prompt.id,
        prompt_text=prompt.prompt_text,
        request_payload=payload,
        response_payload=None,
        status_code=None,
        response_time_ms=elapsed_ms,
        timestamp=datetime.now(UTC),
        error=str(error),
        error_type=error_type,
        outcome="INCONCLUSIVE",
        completion_metadata={"complete": None, "reason": error_type},
        token_estimate=0,
        cost_estimate=0.0,
        active_canaries=active_canaries,
        test_metadata=test_metadata or {},
    )


def _inject_canary_context(payload: Any, canaries: list[str]) -> Any:
    """Place synthetic markers in protected test context without altering user input."""
    if not canaries:
        return payload

    marker = "\nSynthetic security marker for this controlled test: " + ", ".join(canaries)

    if isinstance(payload, dict):
        if "{canary}" in json.dumps(payload):
            return _replace_canary_placeholder(payload, marker)

        messages = payload.get("messages")
        if isinstance(messages, list):
            updated = []
            injected = False
            for message in messages:
                if (
                    isinstance(message, dict)
                    and str(message.get("role", "")).lower() in {"system", "developer"}
                ):
                    message = {**message, "content": str(message.get("content", "")) + marker}
                    injected = True
                updated.append(message)
            if injected:
                return {**payload, "messages": updated}

    return payload


def _replace_canary_placeholder(value: Any, marker: str) -> Any:
    if isinstance(value, dict):
        return {key: _replace_canary_placeholder(item, marker) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_canary_placeholder(item, marker) for item in value]
    if isinstance(value, str):
        return value.replace("{canary}", marker)
    return value


def _estimate_tokens(response_payload: dict[str, Any]) -> int:
    raw = json.dumps(response_payload)
    return max(1, len(raw) // 4)
