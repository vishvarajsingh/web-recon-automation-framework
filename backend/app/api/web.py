from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..schemas import InvestigationCreate, InvestigationRead
from ..services.investigation_service import create_investigation, get_investigation
from ..services.job_service import submit_investigation
from ..services.report_service import safe_report_path
from ..services.target_security import validate_target


router = APIRouter(prefix="/web-api", tags=["public scanner"])


@router.post("/investigations/", response_model=InvestigationRead, status_code=status.HTTP_202_ACCEPTED)
def create_web_investigation(payload: InvestigationCreate, db: Session = Depends(get_db)):
    try:
        validate_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    investigation = create_investigation(db, target=payload.target)
    try:
        submit_investigation(investigation.id, payload.target)
    except Exception as exc:
        investigation.status = "failed"
        investigation.progress = 100
        investigation.progress_message = str(exc)
        db.commit()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Scan could not be queued") from exc
    return investigation


@router.get("/investigations/{investigation_id}", response_model=InvestigationRead)
def read_web_investigation(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return investigation


@router.get("/investigations/{investigation_id}/report/download")
def download_web_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation or not investigation.report_location:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    try:
        report_path = safe_report_path(investigation.report_location)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not report_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file missing")
    return FileResponse(report_path, media_type="application/json", filename=report_path.name)


@router.get("/investigations/{investigation_id}/report/html")
def download_web_html_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation or not investigation.html_report_location:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="HTML report not found")
    try:
        report_path = safe_report_path(investigation.html_report_location)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not report_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="HTML report file missing")
    return FileResponse(report_path, media_type="text/html", filename=report_path.name)