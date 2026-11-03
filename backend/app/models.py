from datetime import datetime, timezone
from sqlalchemy import JSON, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    target = Column(String(255), nullable=False, index=True)
    target_type = Column(String(50), nullable=False, default="domain")
    status = Column(String(50), nullable=False, default="pending")
    risk_score = Column(Integer, nullable=True)
    risk_rating = Column(String(50), nullable=True)
    risk_evidence_status = Column(String(30), nullable=True)
    report_location = Column(String(1024), nullable=True)
    html_report_location = Column(String(1024), nullable=True)
    raw_output = Column(JSON, nullable=True)
    progress = Column(Integer, nullable=False, default=0)
    progress_message = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @property
    def observed_risk_points(self):
        return self.risk_score

    @property
    def risk_interpretation(self):
        if self.risk_evidence_status == "complete":
            return self.risk_rating
        return "Unknown" if self.risk_score is not None else None


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    target_key = Column(String(255), nullable=False, unique=True, index=True)
    canonical_target = Column(String(255), nullable=False)
    target_type = Column(String(50), nullable=False, default="domain")
    first_seen_at = Column(DateTime, nullable=False)
    last_seen_at = Column(DateTime, nullable=False)
