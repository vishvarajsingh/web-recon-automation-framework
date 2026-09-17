from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..schemas import DashboardSummary
from ..security import require_api_key
from ..services.dashboard_service import build_dashboard_summary

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/", response_model=DashboardSummary, dependencies=[Depends(require_api_key)])
def read_dashboard(db: Session = Depends(get_db)):
    return build_dashboard_summary(db)
