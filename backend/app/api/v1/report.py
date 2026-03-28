from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db_session, require_auth
from app.services.scan_service import scan_service

router = APIRouter(dependencies=[Depends(require_auth)])


@router.get("/report/{scan_id}")
async def get_report(
    scan_id: str,
    format: str = Query(default="json", pattern="^(json|markdown)$"),
    session: AsyncSession = Depends(get_db_session),
):
    report = await scan_service.get_report(session, scan_id, format)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    if format == "markdown":
        return PlainTextResponse(report, media_type="text/markdown")

    return report
