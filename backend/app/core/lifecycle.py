from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Scan


class ScanLifecycleManager:
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

    TRANSITIONS: dict[str, set[str]] = {
        CREATED: {QUEUED},
        QUEUED: {RUNNING, FAILED},
        RUNNING: {COMPLETED, FAILED},
        COMPLETED: set(),
        FAILED: set(),
    }

    async def transition_state(self, session: AsyncSession, scan_id: str, to_state: str) -> bool:
        try:
            parsed_scan_id = uuid.UUID(scan_id)
        except ValueError:
            return False

        query = select(Scan).where(Scan.id == parsed_scan_id).with_for_update()
        scan = await session.scalar(query)
        if scan is None:
            return False

        valid_next_states = self.TRANSITIONS.get(scan.status, set())
        if to_state not in valid_next_states:
            return False

        scan.status = to_state
        now = datetime.now(timezone.utc)
        if to_state == self.QUEUED:
            scan.queued_at = now
        elif to_state == self.RUNNING:
            scan.started_at = now
        elif to_state in {self.COMPLETED, self.FAILED}:
            scan.completed_at = now
        return True

    async def get_current_state(self, session: AsyncSession, scan_id: str) -> str | None:
        try:
            parsed_scan_id = uuid.UUID(scan_id)
        except ValueError:
            return None

        scan = await session.get(Scan, parsed_scan_id)
        if scan is None:
            return None
        return scan.status
