from fastapi import APIRouter

from app.api.v1.health import router as health_router
from app.api.v1.report import router as report_router
from app.api.v1.scan import router as scan_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(scan_router, tags=["scan"])
api_router.include_router(report_router, tags=["report"])
