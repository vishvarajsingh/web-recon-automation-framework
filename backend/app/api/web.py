from fastapi import APIRouter, Depends, HTTPException, Path as PathParam, Query, status
from fastapi.responses import FileResponse, HTMLResponse
from pathlib import Path
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..schemas import AssetRead, InvestigationComparisonRequest, InvestigationCreate, InvestigationHistoryItem, InvestigationRead
from ..services.asset_service import asset_history, list_assets
from ..services.investigation_service import create_investigation, get_investigation
from ..services.job_service import submit_investigation
from ..services.report_service import safe_report_path
from ..services.comparison_service import compare_investigations
from reporting.comparison_report import generate_comparison_html
from ..services.target_security import validate_target


router = APIRouter(prefix="/web-api", tags=["public scanner"])


@router.get("/assets")
def read_assets(skip: int = Query(default=0, ge=0, le=100_000), limit: int = Query(default=50, ge=1, le=100), db: Session = Depends(get_db)):
    rows, total = list_assets(db, skip=skip, limit=limit)
    return {"items": [AssetRead(
        id=asset.id,
        canonical_target=asset.canonical_target,
        target_type=asset.target_type,
        first_seen_at=asset.first_seen_at,
        last_seen_at=asset.last_seen_at,
        scan_count=count,
    ).model_dump(mode="json") for asset, count in rows], "total": total, "skip": skip, "limit": limit}


@router.get("/assets/{asset_id}/investigations")
def read_asset_history(asset_id: int = PathParam(gt=0), skip: int = Query(default=0, ge=0, le=100_000), limit: int = Query(default=20, ge=1, le=100), db: Session = Depends(get_db)):
    asset, rows, total = asset_history(db, asset_id, skip=skip, limit=limit)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    items = [InvestigationHistoryItem(
        id=row.id,
        target=row.target,
        status=row.status,
        risk_score=row.risk_score,
        risk_rating=row.risk_rating,
        observed_risk_points=row.risk_score,
        risk_interpretation=row.risk_interpretation,
        risk_evidence_status=row.risk_evidence_status,
        created_at=row.created_at,
        updated_at=row.updated_at,
        has_json_report=bool(row.report_location),
        has_html_report=bool(row.html_report_location),
    ).model_dump(mode="json") for row in rows]
    return {"asset": {"id": asset.id, "canonical_target": asset.canonical_target,
                       "first_seen_at": asset.first_seen_at.isoformat(),
                       "last_seen_at": asset.last_seen_at.isoformat()},
            "items": items, "total": total, "skip": skip, "limit": limit}


@router.post("/investigations/compare")
def compare_scans(payload: InvestigationComparisonRequest, db: Session = Depends(get_db)):
    return compare_investigations(db, payload.previous_id, payload.current_id)


@router.get("/investigations/{previous_id}/compare/{current_id}/report", response_class=HTMLResponse)
def comparison_report(previous_id: int = PathParam(gt=0), current_id: int = PathParam(gt=0), db: Session = Depends(get_db)):
    comparison = compare_investigations(db, previous_id, current_id)
    return HTMLResponse(generate_comparison_html(comparison))


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
    return FileResponse(
        report_path,
        media_type="text/html",
        filename=report_path.name,
        content_disposition_type="inline",
    )


@router.get("/investigations/{investigation_id}/report/{filename}")
def view_web_report_file(investigation_id: int, filename: str, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    report_locations = [investigation.report_location, investigation.html_report_location]
    matching_path = next(
        (path for path in report_locations if path and Path(path).name == filename),
        None,
    )
    if matching_path is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file not found")
    try:
        report_path = safe_report_path(matching_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not report_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report file missing")

    media_type = "text/html" if report_path.suffix.lower() == ".html" else "application/json"
    return FileResponse(
        report_path,
        media_type=media_type,
        filename=report_path.name,
        content_disposition_type="inline",
    )
