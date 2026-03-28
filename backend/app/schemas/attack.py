from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AttackPrompt(BaseModel):
    id: str
    category: str
    prompt_text: str
    description: str
    severity: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackExecutionResult(BaseModel):
    prompt_id: str
    prompt_text: str
    request_payload: dict[str, Any]
    response_payload: dict[str, Any] | None = None
    status_code: int | None = None
    response_time_ms: int | None = None
    timestamp: datetime
    error: str | None = None
    token_estimate: int = 0
    cost_estimate: float = 0.0


class Vulnerability(BaseModel):
    type: str
    severity: str
    attack_prompt: str
    response_text: str
    detection_method: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)
    suggested_fix: str
