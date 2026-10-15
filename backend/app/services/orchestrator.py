from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.attack_library.repository import AttackPromptRepository
from app.core.aggregator import DetectionAggregator
from app.core.cost_tracker import CostTracker
from app.core.lifecycle import ScanLifecycleManager
from app.core.plugin_manager import PluginManager
from app.core.security import decrypt_api_key
from app.db.models import AttackResponseRecord, Scan, TargetConfigRecord, VulnerabilityRecord
from app.schemas.attack import AttackExecutionResult
from app.schemas.scan import ScanConfig
from app.services.executor import AttackExecutor, TargetExecutionConfig

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Main scan workflow coordinator."""

    PROGRESS_COMMIT_BATCH_SIZE = 10

    def __init__(
        self,
        prompt_repository: AttackPromptRepository | None = None,
        plugin_manager: PluginManager | None = None,
        lifecycle_manager: ScanLifecycleManager | None = None,
        aggregator: DetectionAggregator | None = None,
    ) -> None:
        self.prompt_repository = prompt_repository or AttackPromptRepository()
        self.plugin_manager = plugin_manager or PluginManager()
        self.lifecycle_manager = lifecycle_manager or ScanLifecycleManager()
        self.aggregator = aggregator or DetectionAggregator()

    async def execute_scan(self, session: AsyncSession, scan_id: uuid.UUID) -> None:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            raise ValueError(f"Scan not found: {scan_id}")

        if scan.status == ScanLifecycleManager.CREATED:
            transitioned = await self.lifecycle_manager.transition_state(
                session, str(scan.id), ScanLifecycleManager.QUEUED
            )
            if not transitioned:
                raise RuntimeError("Failed to transition scan to queued state")
            await session.commit()

        transitioned = await self.lifecycle_manager.transition_state(
            session, str(scan.id), ScanLifecycleManager.RUNNING
        )
        if not transitioned:
            raise RuntimeError("Failed to transition scan to running state")
        await session.commit()

        config = ScanConfig.model_validate(scan.configuration)
        target_record = await session.scalar(
            select(TargetConfigRecord).where(TargetConfigRecord.scan_id == scan.id)
        )
        if target_record is None:
            raise RuntimeError("Target configuration missing for scan")

        target = TargetExecutionConfig(
            endpoint_url=target_record.endpoint_url,
            api_key=decrypt_api_key(target_record.api_key_encrypted),
            request_template=target_record.request_template,
            headers=target_record.headers,
            timeout=target_record.timeout,
        )

        prompts = self.prompt_repository.load_prompts(config.categories, config.max_prompts)
        scan.total_prompts = len(prompts)
        await session.commit()

        executor = AttackExecutor(
            max_concurrent_requests=config.max_concurrent_requests,
            requests_per_second=config.rate_limit.requests_per_second,
            timeout=config.timeout,
        )
        tracker = CostTracker()

        responses = executor.execute_batch_stream(prompts, target)
        raw_findings = await self._analyze_responses(session, scan, responses, config, tracker)

        aggregated = self.aggregator.aggregate_vulnerabilities(raw_findings)
        session.add_all(
            [
                VulnerabilityRecord(
                    scan_id=scan.id,
                    type=vulnerability.type,
                    severity=vulnerability.severity,
                    attack_prompt=vulnerability.attack_prompt,
                    # Keep the exact model response for reproducible evidence. Secrets are
                    # protected by the access boundary, not by altering forensic evidence.
                    response_text=vulnerability.response_text,
                    detection_method=vulnerability.detection_method,
                    confidence=vulnerability.confidence,
                    evidence=vulnerability.evidence,
                    suggested_fix=vulnerability.suggested_fix,
                )
                for vulnerability in aggregated
            ]
        )

        completed_transition = await self.lifecycle_manager.transition_state(
            session, str(scan.id), ScanLifecycleManager.COMPLETED
        )
        if not completed_transition:
            raise RuntimeError("Failed to transition scan to completed state")

        await session.commit()

        logger.info(
            {
                "event": "scan_completed",
                "scan_id": str(scan.id),
                "prompts": scan.total_prompts,
                "vulnerabilities": len(aggregated),
            }
        )

    async def _analyze_responses(
        self,
        session: AsyncSession,
        scan: Scan,
        responses: AsyncIterable[AttackExecutionResult],
        config: ScanConfig,
        tracker: CostTracker,
    ):
        selected_detectors = self.plugin_manager.get_detectors(config.categories)
        findings = []

        async for response in responses:
            session.add(
                AttackResponseRecord(
                    scan_id=scan.id,
                    prompt_id=response.prompt_id,
                    test_case_id=response.test_case_id or response.prompt_id,
                    prompt_text=response.prompt_text,
                    request_payload=response.request_payload,
                    response_payload=response.response_payload,
                    status_code=response.status_code,
                    response_time_ms=response.response_time_ms,
                    error=response.error,
                    error_type=response.error_type,
                    outcome=response.outcome,
                    completion_metadata=response.completion_metadata,
                    test_metadata=response.test_metadata,
                )
            )

            tracker.track_request(response.token_estimate, response.cost_estimate)
            scan.completed_prompts += 1
            scan.total_requests = tracker.usage.total_requests
            scan.total_tokens = tracker.usage.total_tokens
            scan.total_cost = round(tracker.usage.total_cost, 6)
            logger.info(
                {
                    "event": "scan_prompt_completed",
                    "scan_id": str(scan.id),
                    "prompt_id": response.prompt_id,
                    "completed_prompts": scan.completed_prompts,
                    "total_prompts": scan.total_prompts,
                    "outcome": response.outcome,
                    "error_type": response.error_type,
                }
            )
            # Publish execution progress before detector analysis. A detector must
            # not prevent the status endpoint from observing completed work.
            await session.commit()

            should_continue = tracker.check_limits(
                config.max_requests,
                config.max_tokens,
                config.cost_limit,
            )

            if response.error or not response.response_payload:
                if not should_continue:
                    logger.warning({"event": "scan_limit_reached", "scan_id": str(scan.id)})
                    break
                continue

            if not should_continue:
                logger.warning({"event": "scan_limit_reached", "scan_id": str(scan.id)})
                break

            for detector in selected_detectors:
                detected = await detector.detect(response)
                findings.extend(detected)

        return findings
