from __future__ import annotations

from collections.abc import AsyncGenerator
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.settings import get_settings

settings = get_settings()


def _normalize_database_url(database_url: str) -> str:
    if database_url.startswith("postgresql://"):
        return database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
    return database_url


def _build_connect_args(database_url: str) -> dict[str, object]:
    parsed = urlparse(database_url)
    host = parsed.hostname or ""
    connect_args: dict[str, object] = {}
    if "supabase.co" in host:
        # Supabase pooler requires SSL and works best without asyncpg statement caching.
        connect_args["ssl"] = "require"
        connect_args["statement_cache_size"] = 0
    return connect_args


normalized_database_url = _normalize_database_url(settings.database_url)

engine = create_async_engine(
    normalized_database_url,
    echo=False,
    pool_pre_ping=True,
    pool_size=20,
    max_overflow=10,
    connect_args=_build_connect_args(normalized_database_url),
)

AsyncSessionFactory = async_sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionFactory() as session:
        yield session
