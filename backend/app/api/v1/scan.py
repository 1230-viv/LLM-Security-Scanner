from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db_session, require_auth
from app.schemas.scan import ReplayRequest, ReplayResponse, ScanHistoryItem, ScanStatusResponse, StartScanRequest, StartScanResponse
from app.services.scan_service import scan_service

router = APIRouter(dependencies=[Depends(require_auth)])


@router.post("/scan", response_model=StartScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: StartScanRequest,
    session: AsyncSession = Depends(get_db_session),
) -> StartScanResponse:
    return await scan_service.create_scan(session, payload)


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    session: AsyncSession = Depends(get_db_session),
) -> ScanStatusResponse:
    status_payload = await scan_service.get_scan_status(session, scan_id)
    if status_payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return status_payload


@router.get("/history", response_model=list[ScanHistoryItem])
async def list_scan_history(
    limit: int = 50,
    session: AsyncSession = Depends(get_db_session),
) -> list[ScanHistoryItem]:
    return await scan_service.list_history(session, limit=min(max(limit, 1), 100))


@router.post("/scan/{scan_id}/replay", response_model=ReplayResponse)
async def replay_scan_prompt(
    scan_id: str,
    payload: ReplayRequest,
    session: AsyncSession = Depends(get_db_session),
) -> ReplayResponse:
    replay_result = await scan_service.replay_prompt(session, scan_id, payload)
    if replay_result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Replay target not found")
    return replay_result
