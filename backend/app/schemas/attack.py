from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VulnerabilityVerdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AttackPrompt(BaseModel):
    id: str
    category: str
    prompt_text: str
    description: str = ""
    severity: str = "medium"
    security_property: str | None = None
    technique: str | None = None
    success_criterion: str | None = None
    expected_secure_behavior: str | None = None
    plausible_failure_behavior: str | None = None
    prerequisites: dict[str, Any] = Field(default_factory=dict)
    is_benign_control: bool = False
    reference_label: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def attack_input(self) -> str:
        return self.prompt_text


class AttackExecutionResult(BaseModel):
    prompt_id: str
    test_case_id: str | None = None
    prompt_text: str
    request_payload: dict[str, Any]
    response_payload: dict[str, Any] | None = None
    status_code: int | None = None
    response_time_ms: int | None = None
    timestamp: datetime
    error: str | None = None
    error_type: str | None = None
    outcome: str = "COMPLETED"
    completion_metadata: dict[str, Any] = Field(default_factory=dict)
    token_estimate: int = 0
    cost_estimate: float = 0.0
    active_canaries: list[str] = Field(default_factory=list)
    test_metadata: dict[str, Any] = Field(default_factory=dict)


class Vulnerability(BaseModel):
    type: str
    severity: str
    attack_prompt: str
    response_text: str
    detection_method: str
    confidence: float = Field(ge=0.0, le=1.0)
    verdict: str = Field(default="SUSPECTED")
    evidence: dict[str, Any] = Field(default_factory=dict)
    suggested_fix: str

    def model_post_init(self, __context: Any) -> None:
        if "verdict" not in self.evidence:
            self.evidence["verdict"] = self.verdict
        self.evidence.setdefault("confidence_kind", "heuristic")
