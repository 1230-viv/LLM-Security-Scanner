from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decrypt_api_key, encrypt_api_key
from app.db.models import AttackResponseRecord, Scan, TargetConfigRecord, VulnerabilityRecord
from app.db.session import AsyncSessionFactory
from app.schemas.attack import AttackPrompt
from app.schemas.scan import (
    ReplayRequest,
    ReplayResponse,
    ScanHistoryItem,
    ScanStatusResponse,
    StartScanRequest,
    StartScanResponse,
)
from app.services.executor import AttackExecutor, TargetExecutionConfig
from app.services.orchestrator import ScanOrchestrator
from app.services.reporting import ReportGenerator


class ScanService:
    def __init__(self) -> None:
        self.orchestrator = ScanOrchestrator()
        self.report_generator = ReportGenerator()

    async def create_scan(
        self,
        session: AsyncSession,
        payload: StartScanRequest,
    ) -> StartScanResponse:
        scan = Scan(
            target_endpoint=str(payload.target.endpoint_url),
            status="queued",
            configuration=payload.config.model_dump(mode="json"),
            total_prompts=0,
            completed_prompts=0,
            created_at=datetime.now(timezone.utc),
            queued_at=datetime.now(timezone.utc),
        )
        session.add(scan)
        await session.flush()

        session.add(
            TargetConfigRecord(
                scan_id=scan.id,
                endpoint_url=str(payload.target.endpoint_url),
                api_key_encrypted=encrypt_api_key(payload.target.api_key),
                request_template=payload.target.request_template,
                headers=payload.target.headers,
                timeout=payload.target.timeout,
            )
        )
        await session.commit()

        asyncio.create_task(self._run_scan(scan.id))

        return StartScanResponse(
            scan_id=str(scan.id),
            status=scan.status,
            created_at=scan.created_at,
        )

    async def _run_scan(self, scan_id: uuid.UUID) -> None:
        async with AsyncSessionFactory() as session:
            scan = await session.get(Scan, scan_id)
            if scan is None:
                return

            try:
                await self.orchestrator.execute_scan(session, scan_id)
            except Exception as exc:  # noqa: BLE001
                scan.status = "failed"
                scan.error_message = str(exc)
                scan.completed_at = datetime.now(timezone.utc)
                await session.commit()

    async def get_scan_status(self, session: AsyncSession, scan_id: str) -> ScanStatusResponse | None:
        try:
            parsed_scan_id = uuid.UUID(scan_id)
        except ValueError:
            return None

        scan = await session.get(Scan, parsed_scan_id)
        if scan is None:
            return None

        return ScanStatusResponse(
            scan_id=str(scan.id),
            status=scan.status,
            progress={
                "total_prompts": scan.total_prompts,
                "completed_prompts": scan.completed_prompts,
            },
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            error_message=scan.error_message,
        )

    async def get_report(
        self,
        session: AsyncSession,
        scan_id: str,
        format: str,
    ):
        try:
            parsed_scan_id = uuid.UUID(scan_id)
        except ValueError:
            return None

        scan = await session.get(Scan, parsed_scan_id)
        if scan is None:
            return None

        if format == "markdown":
            return await self.report_generator.generate_markdown_report(session, scan)
        return await self.report_generator.generate_json_report(session, scan)

    async def list_history(self, session: AsyncSession, limit: int = 50) -> list[ScanHistoryItem]:
        query = (
            select(Scan, func.count(VulnerabilityRecord.id))
            .outerjoin(VulnerabilityRecord, VulnerabilityRecord.scan_id == Scan.id)
            .group_by(Scan.id)
            .order_by(desc(Scan.created_at))
            .limit(limit)
        )
        rows = await session.execute(query)

        return [
            ScanHistoryItem(
                scan_id=str(scan.id),
                target_endpoint=scan.target_endpoint,
                status=scan.status,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                vulnerability_count=vulnerability_count,
            )
            for scan, vulnerability_count in rows.all()
        ]

    async def replay_prompt(
        self,
        session: AsyncSession,
        scan_id: str,
        payload: ReplayRequest,
    ) -> ReplayResponse | None:
        try:
            scan_uuid = uuid.UUID(scan_id)
        except ValueError:
            return None

        query = select(AttackResponseRecord).where(
            AttackResponseRecord.scan_id == scan_uuid,
            AttackResponseRecord.prompt_id == payload.prompt_id,
        )
        original = await session.scalar(query)
        if original is None:
            return None

        target = await session.scalar(
            select(TargetConfigRecord).where(TargetConfigRecord.scan_id == scan_uuid)
        )
        if target is None:
            return None

        executor = AttackExecutor(max_concurrent_requests=1, requests_per_second=1, timeout=target.timeout)
        replay_result = await executor.execute_batch(
            prompts=[
                AttackPrompt(
                    id=original.prompt_id,
                    category="replay",
                    prompt_text=original.prompt_text,
                    description="Replay prompt",
                    severity="low",
                    metadata={},
                )
            ],
            target=TargetExecutionConfig(
                endpoint_url=target.endpoint_url,
                api_key=decrypt_api_key(target.api_key_encrypted),
                request_template=target.request_template,
                headers=target.headers,
                timeout=target.timeout,
            ),
        )

        new_response = replay_result[0].response_payload if replay_result else None
        differences = _diff_payload(original.response_payload, new_response)

        return ReplayResponse(
            replay_id=str(uuid.uuid4()),
            original_response=original.response_payload,
            new_response=new_response,
            differences=differences,
        )


def _diff_payload(old: dict | None, new: dict | None) -> list[str]:
    if old == new:
        return []
    if old is None and new is not None:
        return ["Original response was empty"]
    if old is not None and new is None:
        return ["Replay response is empty"]

    differences: list[str] = []
    old_keys = set(old.keys()) if old else set()
    new_keys = set(new.keys()) if new else set()

    for key in sorted(old_keys - new_keys):
        differences.append(f"Missing key in replay response: {key}")
    for key in sorted(new_keys - old_keys):
        differences.append(f"New key in replay response: {key}")
    for key in sorted(old_keys & new_keys):
        if old[key] != new[key]:
            differences.append(f"Value changed for key: {key}")

    return differences


scan_service = ScanService()
