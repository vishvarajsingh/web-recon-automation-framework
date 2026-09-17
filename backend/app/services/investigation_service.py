import ipaddress
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from ..models import Investigation


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
    investigation = Investigation(
        target=target,
        target_type=get_target_type(target),
        status="pending",
        progress=0,
        progress_message="Queued for execution",
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
    db.delete(investigation)
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
    ratings = {
        "Critical": db.query(Investigation).filter(Investigation.risk_rating == "Critical").count(),
        "High": db.query(Investigation).filter(Investigation.risk_rating == "High").count(),
        "Medium": db.query(Investigation).filter(Investigation.risk_rating == "Medium").count(),
        "Low": db.query(Investigation).filter(Investigation.risk_rating == "Low").count(),
        "Informational": db.query(Investigation).filter(Investigation.risk_rating == "Informational").count(),
    }
    return ratings


def recent_investigations(db: Session, limit: int = 5):
    return (
        db.query(Investigation)
        .order_by(Investigation.created_at.desc())
        .limit(limit)
        .all()
    )
