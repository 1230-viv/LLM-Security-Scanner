from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.settings import get_settings
from app.db.session import get_session


async def get_db_session(session: AsyncSession = Depends(get_session)) -> AsyncSession:
    return session


def require_auth(x_scanner_token: str | None = Header(default=None)) -> None:
    settings = get_settings()
    if not settings.api_auth_token:
        return

    if x_scanner_token != settings.api_auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
