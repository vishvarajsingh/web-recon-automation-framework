from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..dependencies import get_db
from ..schemas import InvestigationCreate, InvestigationRead
from ..services.investigation_service import (
    create_investigation,
    delete_investigation,
    get_investigation,
    list_investigations,
    update_investigation,
)
from ..services.job_service import submit_investigation
from ..security import require_api_key
from ..services.target_security import validate_target


class InvestigationListQuery(BaseModel):
    search: str | None = None
    status: str | None = None
    risk_rating: str | None = None
    target_type: str | None = None
    skip: int = 0
    limit: int = 50


router = APIRouter(prefix="/investigations", tags=["investigations"], dependencies=[Depends(require_api_key)])


@router.post("/", response_model=InvestigationRead, status_code=status.HTTP_202_ACCEPTED)
def create_investigation_endpoint(payload: InvestigationCreate, db: Session = Depends(get_db)):
    try:
        validate_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    investigation = create_investigation(db, target=payload.target)
    try:
        submit_investigation(investigation.id, payload.target)
    except Exception as exc:
        update_investigation(db, investigation, status="failed", progress=100, progress_message=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Investigation could not be queued: {exc}",
        )

    return investigation


@router.get("/{investigation_id}", response_model=InvestigationRead)
def read_investigation(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return investigation


@router.get("/", response_model=list[InvestigationRead])
def read_investigations(
    search: str | None = None,
    status: str | None = None,
    risk_rating: str | None = None,
    target_type: str | None = None,
    skip: int = Query(default=0, ge=0, le=10_000),
    limit: int = Query(default=50, ge=1, le=50),
    db: Session = Depends(get_db),
):
    return list_investigations(
        db,
        skip=skip,
        limit=limit,
        search=search,
        status=status,
        risk_rating=risk_rating,
        target_type=target_type,
    )


@router.delete("/{investigation_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_investigation_endpoint(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    delete_investigation(db, investigation)
    return None


@router.post("/{investigation_id}/rerun", response_model=InvestigationRead, status_code=status.HTTP_202_ACCEPTED)
def rerun_investigation(investigation_id: int, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    if not investigation:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    try:
        validate_target(investigation.target)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    try:
        update_investigation(db, investigation, status="pending", progress=0, progress_message="Queued for rerun")
        submit_investigation(investigation.id, investigation.target)
    except Exception as exc:
        update_investigation(db, investigation, status="failed", progress=100, progress_message=str(exc))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Investigation could not be queued: {exc}",
        )

    return investigation
