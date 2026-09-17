from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel
from pydantic import BaseModel, ConfigDict, Field


class InvestigationCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)


class InvestigationRead(BaseModel):
    id: int
    target: str
    target_type: str
    status: str
    risk_score: Optional[int]
    risk_rating: Optional[str]
    report_location: Optional[str]
    html_report_location: Optional[str]
    raw_output: Optional[Dict[str, Any]]
    progress: int
    progress_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class InvestigationSummary(BaseModel):
    total: int
    pending: int
    completed: int
    failed: int


class DashboardInvestigationItem(BaseModel):
    id: int
    target: str
    status: str
    risk_score: int | None
    risk_rating: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DashboardSummary(BaseModel):
    total: int
    pending: int
    completed: int
    failed: int
    risk_distribution: dict[str, int]
    recent_investigations: list[DashboardInvestigationItem]


class ChatMessage(BaseModel):
    role: str
    content: str
