from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.logging import configure_logging
from app.core.rate_limiter import InMemoryRateLimiter
from app.core.settings import get_settings
from app.db.base import Base
from app.db.session import engine

settings = get_settings()
configure_logging(settings.log_level)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.project_name,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

rate_limiter = InMemoryRateLimiter(settings.api_rate_limit_per_minute)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_id = request.client.host if request.client else "unknown"
    allowed = await rate_limiter.allow(client_id)
    if not allowed:
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.on_event("startup")
async def on_startup() -> None:
    async with engine.begin() as connection:
        try:
            await connection.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto;"))
        except Exception:  # noqa: BLE001
            logger.warning({"event": "pgcrypto_extension_unavailable"})
        await connection.run_sync(Base.metadata.create_all)

    logger.info({"event": "startup_complete", "environment": settings.environment})


@app.on_event("shutdown")
async def on_shutdown() -> None:
    await engine.dispose()


app.include_router(api_router, prefix="/api/v1")
