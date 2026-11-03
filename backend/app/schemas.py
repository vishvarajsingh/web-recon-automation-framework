from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel
from pydantic import BaseModel, ConfigDict, Field


class InvestigationCreate(BaseModel):
    target: str = Field(min_length=1, max_length=255)


class InvestigationComparisonRequest(BaseModel):
    previous_id: int = Field(gt=0)
    current_id: int = Field(gt=0)


class InvestigationRead(BaseModel):
    id: int
    asset_id: Optional[int] = None
    target: str
    target_type: str
    status: str
    risk_score: Optional[int] = Field(default=None, description="Deprecated compatibility field; observed risk points where higher means more observed risk.")
    observed_risk_points: Optional[int] = None
    risk_rating: Optional[str] = Field(default=None, description="Deprecated compatibility field; evidence-aware risk interpretation.")
    risk_interpretation: Optional[str] = None
    risk_evidence_status: Optional[str] = None
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
    observed_risk_points: int | None = None
    risk_interpretation: str | None = None
    risk_evidence_status: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DashboardSummary(BaseModel):
    total: int
    pending: int
    completed: int
    failed: int
    risk_distribution: dict[str, int]
    recent_investigations: list[DashboardInvestigationItem]


class AssetRead(BaseModel):
    id: int
    canonical_target: str
    target_type: str
    first_seen_at: datetime
    last_seen_at: datetime
    scan_count: int


class InvestigationHistoryItem(BaseModel):
    id: int
    target: str
    status: str
    risk_score: Optional[int] = Field(default=None, description="Deprecated compatibility field; observed risk points where higher means more observed risk.")
    observed_risk_points: Optional[int] = None
    risk_rating: Optional[str] = Field(default=None, description="Deprecated compatibility field; evidence-aware risk interpretation.")
    risk_interpretation: Optional[str] = None
    risk_evidence_status: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    has_json_report: bool
    has_html_report: bool


class ChatMessage(BaseModel):
    role: str
    content: str
