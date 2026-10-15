from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator

ALLOWED_CATEGORIES = {
    "instruction_override",
    "role_confusion",
    "data_exfiltration",
    "hidden_instruction_extraction",
    "prompt_injection",
    "jailbreak",
    "data_leakage",
    "response_integrity",
    "response_accuracy",
    "instruction_following",
    "synthetic_marker_match",
}


def _contains_prompt_placeholder(value: Any) -> bool:
    if isinstance(value, dict):
        return any(_contains_prompt_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_prompt_placeholder(item) for item in value)
    if isinstance(value, str):
        return "{prompt}" in value
    return False


class RateLimitConfig(BaseModel):
    requests_per_second: float = Field(default=10.0, gt=0.0, le=20.0)


class TargetInput(BaseModel):
    endpoint_url: HttpUrl
    api_key: str | None = Field(default=None, min_length=1)
    request_template: dict[str, Any]
    headers: dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=5, le=120)

    @model_validator(mode="after")
    def validate_prompt_placeholder(self) -> "TargetInput":
        if not _contains_prompt_placeholder(self.request_template):
            raise ValueError("request_template must contain a '{prompt}' placeholder")
        return self


class ScanConfig(BaseModel):
    max_prompts: int = Field(default=100, ge=1, le=1000)
    categories: list[str] = Field(default_factory=lambda: ["instruction_override", "role_confusion", "data_exfiltration", "hidden_instruction_extraction"])
    timeout: int = Field(default=30, ge=5, le=120)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    max_requests: int | None = Field(default=None, ge=1, le=10000)
    max_tokens: int | None = Field(default=None, ge=1, le=10_000_000)
    cost_limit: float | None = Field(default=None, ge=0.0, le=10_000.0)
    max_concurrent_requests: int = Field(default=10, ge=1, le=20)

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, categories: list[str]) -> list[str]:
        invalid = [item for item in categories if item not in ALLOWED_CATEGORIES]
        if invalid:
            raise ValueError(f"Unsupported categories: {', '.join(invalid)}")
        return categories


class StartScanRequest(BaseModel):
    target: TargetInput
    config: ScanConfig = Field(default_factory=ScanConfig)


class StartScanResponse(BaseModel):
    scan_id: str
    status: str
    created_at: datetime


class ScanProgress(BaseModel):
    total_prompts: int
    completed_prompts: int


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: ScanProgress
    created_at: datetime
    completed_at: datetime | None
    error_message: str | None = None


class ReplayRequest(BaseModel):
    prompt_id: str = Field(min_length=1, max_length=100)


class ReplayResponse(BaseModel):
    replay_id: str
    original_response: dict[str, Any] | None
    new_response: dict[str, Any] | None
    differences: list[str]


class ScanHistoryItem(BaseModel):
    scan_id: str
    target_endpoint: str
    status: str
    created_at: datetime
    completed_at: datetime | None
    vulnerability_count: int
