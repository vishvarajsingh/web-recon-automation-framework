from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from .asset_service import normalize_asset_target
from .investigation_service import get_investigation
from .scan_diff import compare_reports


def compare_investigations(db: Session, previous_id: int, current_id: int) -> dict:
    if previous_id == current_id:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Choose two different investigations")
    previous = get_investigation(db, previous_id)
    current = get_investigation(db, current_id)
    if previous is None or current is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    previous_key, _, _ = normalize_asset_target(previous.target)
    current_key, _, _ = normalize_asset_target(current.target)
    if previous_key != current_key:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Investigations must belong to the same normalized target")
    if previous.status != "completed" or current.status != "completed":
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Only completed investigations can be compared")
    if not isinstance(previous.raw_output, dict) or not isinstance(current.raw_output, dict):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Investigation evidence is incomplete")
    return compare_reports(
        previous.raw_output,
        current.raw_output,
        previous_id=previous.id,
        current_id=current.id,
        target=normalize_asset_target(current.target)[1],
        previous_at=previous.created_at.isoformat() if previous.created_at else None,
        current_at=current.created_at.isoformat() if current.created_at else None,
    )
