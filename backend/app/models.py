from datetime import datetime, timezone
from sqlalchemy import JSON, Column, DateTime, Integer, String
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False, index=True)
    target_type = Column(String(50), nullable=False, default="domain")
    status = Column(String(50), nullable=False, default="pending")
    risk_score = Column(Integer, nullable=True)
    risk_rating = Column(String(50), nullable=True)
    report_location = Column(String(1024), nullable=True)
    html_report_location = Column(String(1024), nullable=True)
    raw_output = Column(JSON, nullable=True)
    progress = Column(Integer, nullable=False, default=0)
    progress_message = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
