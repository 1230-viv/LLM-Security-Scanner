from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ReportSummary(BaseModel):
    total_vulnerabilities: int
    high_severity: int
    medium_severity: int
    low_severity: int


class ReportResourceUsage(BaseModel):
    total_requests: int
    total_tokens: int
    total_cost: float


class ReportVulnerability(BaseModel):
    id: str
    type: str
    severity: str
    confidence: float
    attack_prompt: str
    response_text: str
    detection_method: str
    evidence: dict[str, Any]
    suggested_fix: str


class ReportResponse(BaseModel):
    scan_id: str
    target_endpoint: str
    status: str
    created_at: datetime
    completed_at: datetime | None
    scan_duration_seconds: float | None
    resource_usage: ReportResourceUsage
    summary: ReportSummary
    vulnerabilities: list[ReportVulnerability]
