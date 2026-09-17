from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from fastapi.responses import JSONResponse
from pathlib import Path

from ..dependencies import get_db
from ..schemas import InvestigationRead
from ..services.investigation_service import get_investigation

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{investigation_id}", response_model=InvestigationRead)
def read_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation:
        raise HTTPException(status_code=404, detail="Investigation not found")

    if investigation.raw_output is None:
        return JSONResponse(status_code=204, content={})

    return investigation


@router.get("/{investigation_id}/download")
def download_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation or not investigation.report_location:
        raise HTTPException(status_code=404, detail="Report not available")

    report_path = Path(investigation.report_location)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")

    return JSONResponse(content=report_path.read_text(), media_type="application/json")
