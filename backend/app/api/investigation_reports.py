from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..services.investigation_service import get_investigation
from ..security import require_api_key
from ..services.report_service import safe_report_path

router = APIRouter(prefix="/investigations", tags=["investigations"], dependencies=[Depends(require_api_key)])


@router.get("/{investigation_id}/report")
def get_investigation_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation or not investigation.report_location:
        raise HTTPException(status_code=404, detail="Report not found")

    return JSONResponse(content=investigation.raw_output)


@router.get("/{investigation_id}/report/download")
def download_investigation_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation or not investigation.report_location:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        report_path = safe_report_path(investigation.report_location)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file missing")

    return FileResponse(report_path, media_type="application/json", filename=report_path.name)


@router.get("/{investigation_id}/report/html")
def view_investigation_html_report(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation or not investigation.html_report_location:
        raise HTTPException(status_code=404, detail="HTML report not found")
    try:
        report_path = safe_report_path(investigation.html_report_location)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="HTML report file missing")
    return FileResponse(report_path, media_type="text/html", filename=report_path.name)
