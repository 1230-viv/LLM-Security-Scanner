from __future__ import annotations

from datetime import timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.response_processing import sanitize_response_text
from app.db.models import Scan, VulnerabilityRecord
from app.schemas.report import (
    ReportResourceUsage,
    ReportResponse,
    ReportSummary,
    ReportVulnerability,
)

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


class ReportGenerator:
    async def generate_json_report(self, session: AsyncSession, scan: Scan) -> ReportResponse:
        vulnerabilities = await session.scalars(
            select(VulnerabilityRecord).where(VulnerabilityRecord.scan_id == scan.id)
        )
        vulnerability_records = list(vulnerabilities)

        sorted_vulnerabilities = sorted(
            vulnerability_records,
            key=lambda item: (SEVERITY_ORDER.get(item.severity, 0), item.confidence),
            reverse=True,
        )

        high = sum(1 for item in sorted_vulnerabilities if item.severity == "high")
        medium = sum(1 for item in sorted_vulnerabilities if item.severity == "medium")
        low = sum(1 for item in sorted_vulnerabilities if item.severity == "low")

        duration_seconds = None
        if scan.completed_at and scan.created_at:
            duration_seconds = (
                scan.completed_at.astimezone(timezone.utc) - scan.created_at.astimezone(timezone.utc)
            ).total_seconds()

        return ReportResponse(
            scan_id=str(scan.id),
            target_endpoint=scan.target_endpoint,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            scan_duration_seconds=duration_seconds,
            resource_usage=ReportResourceUsage(
                total_requests=scan.total_requests,
                total_tokens=scan.total_tokens,
                total_cost=round(scan.total_cost, 6),
            ),
            summary=ReportSummary(
                total_vulnerabilities=len(sorted_vulnerabilities),
                high_severity=high,
                medium_severity=medium,
                low_severity=low,
            ),
            vulnerabilities=[
                ReportVulnerability(
                    id=str(item.id),
                    type=item.type,
                    severity=item.severity,
                    confidence=item.confidence,
                    attack_prompt=item.attack_prompt,
                    response_text=sanitize_response_text(item.response_text),
                    detection_method=item.detection_method,
                    evidence=item.evidence,
                    suggested_fix=item.suggested_fix,
                )
                for item in sorted_vulnerabilities
            ],
        )

    async def generate_markdown_report(self, session: AsyncSession, scan: Scan) -> str:
        report = await self.generate_json_report(session, scan)

        lines = [
            "# LLM Security Scan Report",
            "",
            f"- Scan ID: {report.scan_id}",
            f"- Target: {report.target_endpoint}",
            f"- Status: {report.status}",
            f"- Total Vulnerabilities: {report.summary.total_vulnerabilities}",
            f"- High / Medium / Low: {report.summary.high_severity} / {report.summary.medium_severity} / {report.summary.low_severity}",
            "",
            "## Resource Usage",
            f"- Requests: {report.resource_usage.total_requests}",
            f"- Tokens: {report.resource_usage.total_tokens}",
            f"- Cost: ${report.resource_usage.total_cost}",
            "",
            "## Findings",
        ]

        if not report.vulnerabilities:
            lines.extend(["", "No vulnerabilities detected."])
            return "\n".join(lines)

        for index, item in enumerate(report.vulnerabilities, start=1):
            lines.extend(
                [
                    "",
                    f"### {index}. {item.type} ({item.severity.upper()})",
                    f"- Confidence: {item.confidence}",
                    f"- Detector: {item.detection_method}",
                    f"- Attack Prompt: {item.attack_prompt}",
                    f"- Response: {sanitize_response_text(item.response_text)[:800]}",
                    f"- Suggested Fix: {item.suggested_fix}",
                ]
            )

        return "\n".join(lines)
