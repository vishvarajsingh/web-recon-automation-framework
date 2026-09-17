from sqlalchemy.orm import Session

from ..schemas import DashboardSummary, DashboardInvestigationItem
from ..services.investigation_service import investigation_summary, risk_distribution, recent_investigations


def build_dashboard_summary(db: Session) -> DashboardSummary:
    summary = investigation_summary(db)
    distribution = risk_distribution(db)
    recent = recent_investigations(db, limit=5)
    recent_items = [
        DashboardInvestigationItem(
            id=item.id,
            target=item.target,
            status=item.status,
            risk_score=item.risk_score,
            risk_rating=item.risk_rating,
            created_at=item.created_at,
        )
        for item in recent
    ]
    return DashboardSummary(
        total=summary["total"],
        pending=summary["pending"],
        completed=summary["completed"],
        failed=summary["failed"],
        risk_distribution=distribution,
        recent_investigations=recent_items,
    )
