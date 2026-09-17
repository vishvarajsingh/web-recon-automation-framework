from fastapi import APIRouter

from . import chat, dashboard, investigation_reports, investigations

api_router = APIRouter()
api_router.include_router(dashboard.router)
api_router.include_router(investigations.router)
api_router.include_router(investigation_reports.router)
api_router.include_router(chat.router)
