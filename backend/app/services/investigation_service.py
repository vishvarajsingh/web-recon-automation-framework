import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import Investigation
from .asset_service import get_or_create_asset


def get_target_type(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return "url"

    if "." in target:
        return "domain"

    return "unknown"


def create_investigation(db: Session, target: str) -> Investigation:
    created_at = datetime.now(timezone.utc).replace(tzinfo=None)
    asset = get_or_create_asset(db, target, seen_at=created_at)
    investigation = Investigation(
        asset_id=asset.id,
        target=target,
        target_type=get_target_type(target),
        status="pending",
        progress=0,
        progress_message="Queued for execution",
        created_at=created_at,
        updated_at=created_at,
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


def update_investigation(db: Session, investigation: Investigation, **kwargs) -> Investigation:
    for key, value in kwargs.items():
        setattr(investigation, key, value)
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation


def delete_investigation(db: Session, investigation: Investigation) -> None:
    asset_id = investigation.asset_id
    db.delete(investigation)
    db.commit()
    if asset_id is not None:
        from ..models import Asset

        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset is not None:
            remaining = (
                db.query(Investigation)
                .filter(Investigation.asset_id == asset_id)
                .order_by(Investigation.created_at.asc(), Investigation.id.asc())
                .all()
            )
            if not remaining:
                db.delete(asset)
            else:
                asset.first_seen_at = remaining[0].created_at
                asset.last_seen_at = remaining[-1].created_at
            db.commit()


def get_investigation(db: Session, investigation_id: int) -> Investigation | None:
    return db.query(Investigation).filter(Investigation.id == investigation_id).first()


def list_investigations(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    search: str | None = None,
    status: str | None = None,
    risk_rating: str | None = None,
    target_type: str | None = None,
):
    query = db.query(Investigation).order_by(Investigation.created_at.desc())
    if search:
        query = query.filter(Investigation.target.ilike(f"%{search}%"))
    if status:
        query = query.filter(Investigation.status == status)
    if risk_rating:
        query = query.filter(Investigation.risk_rating == risk_rating)
    if target_type:
        query = query.filter(Investigation.target_type == target_type)
    return query.offset(skip).limit(limit).all()


def investigation_summary(db: Session) -> dict:
    total = db.query(Investigation).count()
    pending = db.query(Investigation).filter(Investigation.status == "pending").count()
    completed = db.query(Investigation).filter(Investigation.status == "completed").count()
    failed = db.query(Investigation).filter(Investigation.status == "failed").count()
    return {
        "total": total,
        "pending": pending,
        "completed": completed,
        "failed": failed,
    }


def risk_distribution(db: Session) -> dict[str, int]:
    completed = db.query(Investigation).filter(Investigation.status == "completed")
    known = completed.filter(Investigation.risk_evidence_status == "complete")
    ratings = {
        label: known.filter(Investigation.risk_rating == label).count()
        for label in ("Critical", "High", "Medium", "Low", "Informational")
    }
    ratings["Unknown"] = completed.filter(
        (Investigation.risk_evidence_status != "complete") | (Investigation.risk_evidence_status.is_(None))
    ).count()
    return ratings


def recent_investigations(db: Session, limit: int = 5):
    return (
        db.query(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
        .all()
    )
