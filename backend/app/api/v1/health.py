from fastapi import APIRouter
from sqlalchemy import text

from app.db.session import AsyncSessionFactory

router = APIRouter()


@router.get("/health")
async def health_check() -> dict[str, str]:
    async with AsyncSessionFactory() as session:
        await session.execute(text("SELECT 1"))
    return {"status": "healthy", "database": "connected", "version": "1.0.0"}
